import datetime
import json
import logging
import os
import re
import urllib.request

import appdirs
import requests
import requests_cache

from .text import basename
from .utils import get_latest, read, write


def fetch_init_cache(log):
    cache = appdirs.user_cache_dir("ietf-reviewtool")
    if not os.path.isdir(cache):
        os.mkdir(cache)
    log.debug("Using cache directory %s", cache)
    requests_cache.install_cache(
        cache_name=os.path.join(cache, "ietf-reviewtool"),
        backend="sqlite",
        expire_after=datetime.timedelta(days=30),
    )


def fetch_url(url: str, log: logging.Logger, use_cache: bool = True, method: str = "GET") -> str:
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
            return None

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
            if use_cache is False:
                with requests_cache.disabled():
                    response = requests.request(
                        method,
                        url,
                        allow_redirects=True,
                        timeout=20,
                        headers=headers,
                    )
            else:
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
            return None
        return response.text


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
    if content is not None:
        result = json.loads(content)
        return result["objects"] if "objects" in result else result
    return None


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
        return None

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

    return text if len(events) == 1 else None


def fetch_docs_in_last_call_text(name: str, log: logging.Logger) -> list:
    """
    Fetches IDs and RFCs mentioned in the last-call message. The *assumption*
    is that they are all called-out downrefs.

    @param      name  The name of this document.

    @return     The RFC numbers mention in the last-call email.
    """
    last_call = read("last_call_text/" + name, log)
    if not last_call:
        return []
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
        return None
    return json.loads(meta)
