"""ietf-reviewtool fetch module"""

import asyncio
import base64
import datetime
import gzip
import json
import logging
import os
import re
import threading
import urllib.request
from typing import Any, cast

import hishel
import httpx
import platformdirs
from hishel import BaseFilter, FilterPolicy
from hishel.httpx import AsyncCacheClient, AsyncCacheTransport

from .text import basename, strip_pagination
from .utils import get_latest, read, write


class _ForceCache(BaseFilter):
    """Cache 2xx responses for our TTL, ignoring HTTP cache-control headers.

    Error responses (4xx/5xx) are intentionally NOT cached so that transient
    failures don't poison the cache for 30 days.
    """

    def needs_body(self) -> bool:
        return False

    def apply(self, item: Any, body: bytes | None) -> bool:
        return bool(200 <= item.status_code < 300)


_CACHE_POLICY = FilterPolicy(response_filters=[_ForceCache()])

# ---------------------------------------------------------------------------
# Background event loop — all async HTTP runs here, bridged from sync code.
# ---------------------------------------------------------------------------
_loop = asyncio.new_event_loop()
threading.Thread(target=_loop.run_forever, daemon=True, name="irt-fetch").start()


def run_async(coro: Any) -> Any:
    """Submit a coroutine to the background loop and block until done.

    MUST NOT be called from within a coroutine already running on _loop —
    that would deadlock. Inside fetch_parallel tasks, call the _async
    variants (fetch_url_async, fetch_dt_async, fetch_meta_async) directly.
    """
    return asyncio.run_coroutine_threadsafe(coro, _loop).result()


# Private alias kept for internal use within this module.
_run = run_async


# ---------------------------------------------------------------------------
# HTTP clients (lazy, initialised on first use inside the event loop).
# ---------------------------------------------------------------------------
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/90.0.4430.72 Safari/537.36"
    )
}
_LIMITS = httpx.Limits(max_connections=64, max_keepalive_connections=32)
_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)

_client: httpx.AsyncClient | None = None
_cached_client: httpx.AsyncClient | None = None


def _plain_transport() -> httpx.AsyncHTTPTransport:
    # http3=True can be added here once httpx exposes stable H3 support.
    return httpx.AsyncHTTPTransport(http2=True, limits=_LIMITS)


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            transport=_plain_transport(),
            headers=_HEADERS,
            follow_redirects=True,
            timeout=_TIMEOUT,
        )
    return _client


async def _get_cached_client(
    log: logging.Logger | None = None,
) -> httpx.AsyncClient:
    global _cached_client
    if _cached_client is None:
        cache_dir = platformdirs.user_cache_dir("ietf-reviewtool")
        os.makedirs(cache_dir, exist_ok=True)
        if log:
            log.debug("Using cache directory %s", cache_dir)
        storage = hishel.AsyncSqliteStorage(
            database_path=os.path.join(cache_dir, "ietf-reviewtool.db"),
            default_ttl=datetime.timedelta(days=30).total_seconds(),
        )
        _cached_client = AsyncCacheClient(
            transport=AsyncCacheTransport(
                next_transport=_plain_transport(),
                storage=storage,
                policy=_CACHE_POLICY,
            ),
            headers=_HEADERS,
            follow_redirects=True,
            timeout=_TIMEOUT,
        )
    return _cached_client


# ---------------------------------------------------------------------------
# Async fetch primitives — call these inside fetch_parallel lambdas.
# ---------------------------------------------------------------------------


async def fetch_url_async(
    url: str,
    log: logging.Logger,
    use_cache: bool = True,
    method: str = "GET",
) -> str | None:
    if url.startswith("ftp:") or url.startswith("file:"):
        try:
            log.debug("%s nocache %s", method.lower(), url)
            with urllib.request.urlopen(url) as response:
                return cast(str, response.read())
        except urllib.error.URLError as err:
            log.debug("%s -> %s", url, err)
            return None

    client = await (_get_cached_client(log) if use_cache else _get_client())
    extra_headers: dict[str, str] = {}

    log.debug("%s %scache %s", method.lower(), "" if use_cache else "no", url)
    while True:
        try:
            response = await client.request(method, url, headers=extra_headers or None)
            if method == "HEAD" and response.status_code == 403 and response.history:
                log.debug(
                    "%s -> redirect to %s -> 403 (treating as valid)",
                    url,
                    str(response.url),
                )
                return ""
            response.raise_for_status()
        except httpx.HTTPStatusError as err:
            log.debug("%s -> %s", url, err)
            if method == "HEAD":
                log.debug("Retrying %s with Range-header GET", url)
                extra_headers["Range"] = "bytes=0-100"
                method = "GET"
                continue
            return None
        except httpx.RequestError as err:
            log.debug("%s -> %s", url, err)
            return None
        return response.text if method != "HEAD" else ""


async def fetch_dt_async(datatracker: str, query: str, log: logging.Logger) -> dict:
    api = "/api/v1/"
    if not query.startswith(api):
        query = api + query
    query += "&format=json" if "?" in query else "?format=json"
    content = await fetch_url_async(datatracker + query, log)
    if content:
        result = json.loads(content)
        objects = result["objects"] if "objects" in result else result
        return cast(dict[Any, Any], objects)
    return {}


async def fetch_meta_async(datatracker: str, doc: str, log: logging.Logger) -> dict:
    url = datatracker + "/doc/" + doc + "/doc.json"
    meta = await fetch_url_async(url, log)
    if not meta:
        log.info("No metadata available for %s", doc)
        return {}
    return cast(dict[Any, Any], json.loads(meta))


# ---------------------------------------------------------------------------
# Sync wrappers — for single calls from non-async code.
# ---------------------------------------------------------------------------


def fetch_url(
    url: str, log: logging.Logger, use_cache: bool = True, method: str = "GET"
) -> str | None:
    return cast(str | None, _run(fetch_url_async(url, log, use_cache, method)))


def fetch_dt(datatracker: str, query: str, log: logging.Logger) -> dict:
    return cast(dict[Any, Any], _run(fetch_dt_async(datatracker, query, log)))


def fetch_meta(datatracker: str, doc: str, log: logging.Logger) -> dict:
    return cast(dict[Any, Any], _run(fetch_meta_async(datatracker, doc, log)))


# ---------------------------------------------------------------------------
# Parallel fetch — tasks must be callables returning coroutines.
# ---------------------------------------------------------------------------


def fetch_parallel(tasks: dict) -> dict:
    """Run coroutine-returning callables in parallel on the background loop.

    Usage:
        fetch_parallel({n: lambda n=n: fetch_meta_async(dt, n, log) for n in names})
    """

    async def _gather() -> dict:
        keys = list(tasks.keys())
        results = await asyncio.gather(*[tasks[k]() for k in keys])
        return dict(zip(keys, results))

    return cast(dict, _run(_gather()))


# ---------------------------------------------------------------------------
# Higher-level helpers (sequential by design — fallback logic inside).
# ---------------------------------------------------------------------------


def get_writeups(datatracker: str, item: str, log: logging.Logger) -> str | None:
    doc_events = fetch_dt(
        datatracker, "doc/writeupdocevent/?doc__name=" + basename(item), log
    )
    if not doc_events:
        return ""

    events = {
        e["type"]
        for e in doc_events
        if e["type"]
        not in [
            "changed_ballot_approval_text",
            "changed_action_announcement",
            "changed_review_announcement",
        ]
    }
    if events:
        log.debug(events)
    text = None
    for evt in events:
        type_events = [e for e in doc_events if e["type"] == evt]
        text = get_latest(type_events, "time")["text"]

        directory = re.sub(r"^(?:changed_)?(.*)?", r"\1", evt)
        if not os.path.isdir(directory):
            os.mkdir(directory)

        if text:
            write(text, os.path.join(directory, item + ".txt"))
        else:
            log.debug("no %s for %s", evt, item)

    return text if len(events) == 1 else ""


def fetch_docs_in_last_call_text(name: str, log: logging.Logger) -> set:
    last_call = read("last_call_text/" + name, log)
    if not last_call:
        return set()
    docs = re.findall(
        r"rfc\s*\d+|draft-[-a-z\d_]+",
        last_call,
        flags=re.IGNORECASE,
    )
    docs = [re.sub(r"-\d+$", "", re.sub(r"\s+", "", n.lower())) for n in docs]
    return set(docs)


def get_items(
    items: list,
    log: logging.Logger,
    datatracker: str,
    strip: bool = True,
    get_writeup: bool = False,
    get_xml: bool = True,
    extract_md: bool = True,
) -> list:
    result = []
    for item in items:
        do_strip = strip
        file_name = item
        if not file_name.endswith(".txt") and not file_name.endswith(".xml"):
            file_name += ".txt"

        if os.path.isfile(file_name):
            log.warning("%s exists, skipping", file_name)
            result.append(file_name)
            continue

        log.debug("Getting %s", item)
        text = ""
        url = ""
        match = re.search(r"^(conflict-review|status-change)-", item)
        if item.startswith("draft-"):
            url = "https://ietf.org/archive/id/" + file_name
        elif item.startswith("rfc"):
            url = "https://rfc-editor.org/rfc/" + file_name
        elif item.startswith("charter-"):
            url_pattern = re.sub(
                r"(.*)(((-\d+){2}).txt)$", r"\1/withmilestones\2", file_name
            )
            url = datatracker + "/doc/" + url_pattern
            do_strip = False
        elif match:
            which = match[1]
            if which == "conflict-review":
                doc = re.sub(which + r"-(.*)", r"draft-\1", item)
            else:
                continue
            text = get_writeups(datatracker, doc, log) or ""
            doc = basename(doc)
            slug = "conflrev" if which == "conflict-review" else "statchg"
            target = fetch_dt(
                datatracker,
                f"doc/relateddocument/?relationship__slug={slug}&target__name={doc}",
                log,
            )
            if not target:
                log.warning("cannot find target for %s", doc)
                continue
            alias = fetch_dt(datatracker, target[0]["target"], log)
            if not alias:
                log.warning("cannot find alias for %s", target[0]["target"])
                continue
            items.append(f"{alias['name']}-{alias['rev']}.txt")
            do_strip = False

        if not text and url:
            text = fetch_url(url, log) or ""
            if not text and not re.match(r"-\d{2}$", item):
                log.debug("No text found, trying to fetch latest revision")
                meta = fetch_dt(datatracker, f"doc/document/{item}", log)
                if "rev" not in meta:
                    log.warning("No datatracker info found for %s", item)
                else:
                    rev = meta["rev"]
                    item = f"{item}-{rev}"
                    file_name = f"{item}.txt"
                    url = f"https://ietf.org/archive/id/{file_name}"
                    text = fetch_url(url, log) or ""

        if text:
            if file_name.endswith(".xml") and extract_md:
                mkd = re.search(
                    r"<!--\s*##markdown-source:(.*)-->",
                    text,
                    flags=re.DOTALL,
                )
                if mkd:
                    log.debug("Extracting Markdown source of %s", file_name)
                    mkd_file = re.sub(r"\.xml$", ".md", file_name)
                    with open(mkd_file, "wb") as file:
                        file.write(gzip.decompress(base64.b64decode(mkd[1])))
                    result.append(mkd_file)
            elif do_strip:
                log.debug("Stripping %s", item)
                text = strip_pagination(text)
            write(text, file_name)
            result.append(file_name)

        if get_writeup and not file_name.endswith(".xml"):
            get_writeups(datatracker, item, log)

        if get_xml and item.startswith("draft-") and file_name.endswith(".txt"):
            items.append(re.sub(r"\.txt$", ".xml", file_name))

    return result
