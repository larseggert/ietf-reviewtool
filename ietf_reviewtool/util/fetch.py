"""ietf-reviewtool fetch module"""

import base64
import datetime
import gzip
import json
import logging
import os
import re
import urllib.request

import appdirs
import requests
import requests_cache

from typing import Optional

from .text import basename, strip_pagination
from .utils import get_latest, read, write


def fetch_init_cache(log: Optional[logging.Logger] = None) -> None:
    """
    Initialize the fetch cache.

    @param      log   The log to write to
    """
    cache = appdirs.user_cache_dir("ietf-reviewtool")
    if not os.path.isdir(cache):
        os.mkdir(cache)
    if log:
        log.debug("Using cache directory %s", cache)
    requests_cache.install_cache(
        cache_name=os.path.join(cache, "ietf-reviewtool"),
        backend="sqlite",
        allowable_codes=[200],
        stale_if_error=False,
        match_headers=True,
        expire_after=datetime.timedelta(days=30),
    )


def fetch_url(
    url: str, log: logging.Logger, use_cache: bool = True, method: str = "GET"
) -> str:
    """
    Fetches the resource at the given URL or checks its reachability (when
    method is "HEAD".) A failing HEAD request is retried as a GET, since some
    servers apparently don't like HEAD.

    @param      url        The URL to fetch
    @param      log        The log to write to
    @param      use_cache  Whether to use the local cache or not
    @param      method     The method to use (default "GET")

    @return     The decoded content of the resource (or the empty string for a
                successful HEAD request). None if an error occurred.
    """
    if url.startswith("ftp:") or url.startswith("file:"):
        try:
            log.debug(
                "%s %scache %s",
                method.lower(),
                "no" if not use_cache else "",
                url,
            )
            with urllib.request.urlopen(url) as response:
                return response.read()
        except urllib.error.URLError as err:
            log.debug("%s -> %s", url, err)
            return ""

    while True:
        try:
            log.debug(
                "%s %scache %s",
                method.lower(),
                "no" if not use_cache else "",
                url,
            )
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/90.0.4430.72 Safari/537.36"
                )
            }
            if use_cache:
                if requests_cache.is_installed() is False:
                    fetch_init_cache(log)
            else:
                if requests_cache.is_installed():
                    requests_cache.uninstall_cache()

            response = requests.request(
                method,
                url,
                allow_redirects=True,
                timeout=20,
                headers=headers,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            log.debug("%s -> %s", url, err)
            if method == "HEAD":
                log.debug("Retrying %s with Range-header GET", url)
                headers["Range"] = "bytes=0-100"
                method = "GET"
                continue
            return ""
        return response.text if method != "HEAD" else response


def fetch_dt(datatracker: str, query: str, log: logging.Logger) -> dict:
    """
    Return dict of JSON query results from datatracker.

    @param      datatracker  The datatracker URL to use
    @param      query        The query to return data for

    @return     The query results.
    """
    api = "/api/v1/"
    if not query.startswith(api):
        query = api + query
    if re.search(r"\?", query):
        query += "&format=json"
    else:
        query += "?format=json"
    content = fetch_url(datatracker + query, log)
    if content:
        result = json.loads(content)
        return result["objects"] if "objects" in result else result
    return {}


def get_writeups(datatracker: str, item: str, log: logging.Logger) -> str:
    """
    Download related document writeups for an item from the datatracker.

    @param      datatracker  The datatracker URL to use
    @param      item         The item to download write-ups for
    @param      log          The log to write to

    @return     The text of the writeup, if only a single one existed, else
                None.
    """
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
    """
    Fetches IDs and RFCs mentioned in the last-call message. The *assumption*
    is that they are all called-out downrefs.

    @param      name  The name of this document.

    @return     The RFC numbers mention in the last-call email.
    """
    last_call = read("last_call_text/" + name, log)
    if not last_call:
        return set()
    docs = re.findall(
        r"rfc\s*\d+|draft-[-a-z\d_]+",
        last_call,
        flags=re.IGNORECASE,
    )

    docs = [re.sub(r"\s+", "", n.lower()) for n in docs]
    docs = [re.sub(r"-\d+$", "", n) for n in docs]
    return set(docs)


def fetch_meta(datatracker: str, doc: str, log: logging.Logger) -> dict:
    """
    Fetches metadata for doc from datatracker.

    @param      datatracker  The datatracker URL to use
    @param      doc          The document to fetch metadata for

    @return     The metadata, or None
    """
    url = datatracker + "/doc/" + doc + "/doc.json"
    meta = fetch_url(url, log)
    if not meta:
        log.info("No metadata available for %s", doc)
        return {}
    return json.loads(meta)


def get_items(
    items: list,
    log: logging.Logger,
    datatracker: str,
    strip: bool = True,
    get_writeup=False,
    get_xml=True,
    extract_md=True,
) -> list:
    """
    Download named items into files of the same name in the current directory.
    Does not overwrite existing files. Names need to include the revision, and
    may or may not include the ".txt" suffix.

    @param      items        The items to download
    @param      datatracker  The datatracker URL to use
    @param      strip        Whether to run strip() on the downloaded item
    @param      get_writeup  Whether to download associated write-ups
    @param      get_xml      Whether to download XML sources
    @param      extract_md   Whether to extract Markdown from XML sources

    @return     List of file names written or existing
    """
    result = []
    for item in items:
        do_strip = strip
        file_name = item
        if not file_name.endswith(".txt") and not file_name.endswith(".xml"):
            file_name += ".txt"

        if get_writeup:
            get_writeups(datatracker, item, log)

        if get_xml and item.startswith("draft-") and file_name.endswith(".txt"):
            # also try and get XML source
            items.append(re.sub(r"\.txt$", ".xml", file_name))

        if os.path.isfile(file_name):
            log.warning("%s exists, skipping", file_name)
            result.append(file_name)
            continue

        log.debug("Getting %s", item)
        cache = None
        text = ""
        url = ""
        match = re.search(r"^(conflict-review|status-change)-", item)
        if item.startswith("draft-"):
            url = "https://ietf.org/archive/id/" + file_name
            cache = os.getenv("IETF_IDS")
        elif item.startswith("rfc"):
            url = "https://rfc-editor.org/rfc/" + file_name
            cache = os.getenv("IETF_RFCS")
        elif item.startswith("charter-"):
            url_pattern = re.sub(
                r"(.*)(((-\d+){2}).txt)$", r"\1/withmilestones\2", file_name
            )
            url = datatracker + "/doc/" + url_pattern
            # the charters in rsync don't have milestones, can't use
            # cache = os.getenv("IETF_CHARTERS")
            do_strip = False
        elif match:
            which = match[1]
            if which == "conflict-review":
                doc = re.sub(which + r"-(.*)", r"draft-\1", item)
            else:
                # FIXME: figure out how to download status change text
                continue
            text = get_writeups(datatracker, doc, log)
            # in-progress conflict-reviews/status-changes are not in the cache
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
        # else:
        #     die(f"Unknown item type: {item}", log)

        if cache:
            cache_file = os.path.join(cache, file_name)
            if os.path.isfile(cache_file):
                log.debug("Using cached %s", item)
                text = read(cache_file, log)
            else:
                log.debug("No cached copy of %s in %s", item, cache)

        if not text and url:
            text = fetch_url(url, log)

        if text:
            if file_name.endswith(".xml") and extract_md:
                # try and extract markdown
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

    return result
