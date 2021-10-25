#! /usr/bin/env python3

"""
Review tool for IETF documents.

Copyright (C) 2021  Lars Eggert

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA  02110-1301, USA.

SPDX-License-Identifier: GPL-2.0
"""

import datetime
import difflib
import html
import itertools
import json
import logging
import math
import os
import re
import sys
import tempfile
import textwrap
import urllib.parse
import urllib.request
import xml.etree.ElementTree

import appdirs
import charset_normalizer
import click
import language_tool_python
import requests
import requests_cache
import yaml

log = logging.getLogger(__name__)

# pattern matching section headings
SECTION_PATTERN = re.compile(
    r"""^(?:[\- ]\s)?(Abstract|Status\sof\sThis\sMemo|Copyright\sNotice|
        Table\sof\sContents|Author(?:'?s?'?)?\sAddress(?:es)?|
        (?:Appendix\s+)?[\dA-Z]+(?:\.\d+)*\.?\s|
        \d+(?:\.\d+)*\.?)(.*)""",
    re.VERBOSE,
)

# pattern matching RFC2119 keywords
KEYWORDS_PATTERN = re.compile(
    r"""\W(MUST(?:\s+NOT)?|REQUIRED|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|
        (?:NOT\s+)?RECOMMENDED|MAY|OPTIONAL)\W""",
    re.VERBOSE,
)

# pattern matching RFC2119 keywords used with lowercase "not"
LC_NOT_KEYWORDS_PATTERN = re.compile(
    r"""\W((?:MUST|SHALL|SHOULD)\s+not|not\s+RECOMMENDED)\W""",
    re.VERBOSE,
)


# pattern matching variants of the RFC8174 boilerplate text
BOILERPLATE_8174_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+
        "SHALL",\s+"SHALL\s+NOT",\s+"SHOULD",\s+"SHOULD\s+NOT",\s+
        "RECOMMENDED",\s+"NOT\s+RECOMMENDED",\s+"MAY",\s+and\s+
        "OPTIONAL"\s+in\s+this\s+document\s+are\s+to\s+be\s+interpreted\s+
        as\s+described\s+in\s+\[?BCP\s*14\]?,?\s*\[?RFC\s*2119\]?,?\s*
        (?:and\s+)?\[?RFC\s*8174\]?,?\s+when,\s+and\s+only\s+when,\s+
        they\s+appear\s+in\s+all\s+capitals,\s+as\s+shown\s+
        (?:above|here)\.""",
    re.VERBOSE | re.MULTILINE,
)

# pattern matching variants of the RFC2119 boilerplate text
BOILERPLATE_2119_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+
        "SHALL",\s+"SHALL\s+NOT",\s+"SHOULD",\s+"SHOULD\s+NOT",\s+
        "RECOMMENDED",\s+(?:"NOT\s+RECOMMENDED",\s+)?"MAY",\s+and\s+
        "OPTIONAL"\s+in\s+this\s+document\s+are\s+to\s+be\s+interpreted\s+
        as\s+described\s+in\s+\[?RFC\s*2119\]?\.""",
    re.VERBOSE | re.MULTILINE,
)

# pattern matching the beginning of the RFC2119/RFC8174 boilerplate text
BOILERPLATE_BEGIN_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+""",
)


TLP_6A_PATTERN = re.compile(
    r"""\s*This\s+Internet-Draft\s+is\s+submitted\s+in\s+full\s+conformance\s+
        with\s+the\s+provisions\s+of\s+BCP\s*78\s+and\s+BCP\s*79\.\s+""",
    re.VERBOSE,
)

ID_GUIDELINES_PATTERNS = [
    (
        True,
        re.compile(
            # this has an option for the pre-2010 text in it
            r"""Internet-Drafts\s+are\s+working\s+documents\s+of\s+the\s+
            Internet\s+Engineering\s+Task\s+Force\s+\(IETF\)
            (,\s+its\s+areas,\s+and\s+its\s+working\s+groups)?\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""Note\s+that\s+other\s+groups\s+may\s+also\s+distribute\s+
            working\s+documents\s+as\s+Internet-Drafts\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""The\s+list\s+of\s+current\s+Internet-Drafts\s+is\s+at\s+
            https?://datatracker\.ietf\.org/drafts/current/?\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""Internet-Drafts\s+are\s+draft\s+documents\s+valid\s+for\s+a\s+
            maximum\s+of\s+six\s+months\s+and\s+may\s+be\s+updated,\s+
            replaced,\s+or\s+obsoleted\s+by\s+other\s+documents\s+at\s+any\s+
            time.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""It\s+is\s+inappropriate\s+to\s+use\s+Internet-Drafts\s+as\s+
            reference\s+material\s+or\s+to\s+cite\s+them\s+other\s+than\s+as\s+
            \"work\s+in\s+progress(\.\"|\"\.)\s+""",
            re.VERBOSE,
        ),
    ),
    # this are not part of the boilerplate, but xml2rfc adds it?
    (
        False,
        re.compile(
            r"""This\s+Internet-Draft\s+will\s+expire\s+on\s+
            (\d{1,2}\s+[A-Za-z]+\s+\d{4}|[A-Za-z]+\s+\d{1,2},\s+\d{4})\.\s+""",
            re.VERBOSE,
        ),
    ),
    # this is pre-2010 text:
    (
        False,
        re.compile(
            r"""The\s+list\s+of\s+current\s+Internet-Drafts\s+can\s+be\s+
            accessed\s+at\s+https?://www\.ietf\.org/1id-abstracts\.
            html\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        False,
        re.compile(
            r"""The\s+list\s+of\s+Internet-Draft\s+Shadow\s+Directories\s+can\s+
            be\s+accessed\s+at\s+https?://www\.ietf\.org/shadow\.html\.\s+""",
            re.VERBOSE,
        ),
    ),
]

COPYRIGHT_ALT_STREAMS = r"""Copyright\s+\(c\)\s+20\d{2}\s+IETF\s+Trust\s+
        and\s+the\s+persons\s+identified\s+as\s+the\s+document\s+authors\.\s+
        All\s+rights\s+reserved\.\s+
        This\s+document\s+is\s+subject\s+to\s+BCP\s*78\s+and\s+the\s+IETF\s+
        Trust's\s+Legal\s+Provisions\s+Relating\s+to\s+IETF\s+Documents\s+
        \(https?://trustee\.ietf\.org/license-info\)\s+in\s+effect\s+on\s+
        the\s+date\s+of\s+publication\s+of\s+this\s+document\.\s+
        Please\s+review\s+these\s+documents\s+carefully,\s+as\s+they\s+
        describe\s+your\s+rights\s+and\s+restrictions\s+with\s+respect\s+
        to\s+this\s+document\.\s*"""

COPYRIGHT_IETF = re.compile(
    COPYRIGHT_ALT_STREAMS
    + r"""Code\s+Components\s+extracted\s+from\s+
        this\s+document\s+must\s+include\s+(Simplified|Revised)\s+BSD\s+
        License\s+text\s+as\s+described\s+in\s+Section\s+4\.e\s+of\s+
        the\s+Trust\s+Legal\s+Provisions\s+and\s+are\s+provided\s+
        without\s+warranty\s+as\s+described\s+in\s+the\s+
        (Simplified|Revised)\s+BSD\s+License\.\s*""",
    re.VERBOSE,
)

COPYRIGHT_ALT_STREAMS = re.compile(
    COPYRIGHT_ALT_STREAMS,
    re.VERBOSE,
)

NO_MOD_RFC = re.compile(
    r"""This\s+document\s+may\s+not\s+be\s+modified,\s+and\s+derivative\s+
    works\s+of\s+it\s+may\s+not\s+be\s+created,\s+except\s+to\s+format\s+it\s+
    for\s+publication\s+as\s+an\s+RFC\s+or\s+to\s+translate\s+it\s+into\s+
    languages\s+other\s+than\s+English\.\s*""",
    re.VERBOSE,
)

NO_MOD_NO_RFC = re.compile(
    r"""This\s+document\s+may\s+not\s+be\s+modified,\s+and\s+derivative\s+
    works\s+of\s+it\s+may\s+not\s+be\s+created,\s+and\s+it\s+may\s+not\s+be\s+
    published\s+except\s+as\s+an\s+Internet-Draft\.\s*""",
    re.VERBOSE,
)

PRE_5378 = re.compile(
    r"""This\s+document\s+may\s+contain\s+material\s+from\s+IETF\s+Documents\s+
    or\s+IETF\s+Contributions\s+published\s+or\s+made\s+publicly\s+available\s+
    before\s+November\s+10,\s+2008\.\s+
    The\s+person\(s\)\s+controlling\s+the\s+copyright\s+in\s+some\s+of\s+this\s+
    material\s+may\s+not\s+have\s+granted\s+the\s+IETF\s+Trust\s+the\s+right\s+
    to\s+allow\s+modifications\s+of\s+such\s+material\s+outside\s+the\s+IETF\s+
    Standards\s+Process\.\s+
    Without\s+obtaining\s+an\s+adequate\s+license\s+from\s+the\s+person\(s\)\s+
    controlling\s+the\s+copyright\s+in\s+such\s+materials,\s+this\s+document\s+
    may\s+not\s+be\s+modified\s+outside\s+the\s+IETF\s+Standards\s+Process,\s+
    and\s+derivative\s+works\s+of\s+it\s+may\s+not\s+be\s+created\s+outside\s+
    the\s+IETF\s+Standards\s+Process,\s+except\s+to\s+format\s+it\s+for\s+
    publication\s+as\s+an\s+RFC\s+or\s+to\s+translate\s+it\s+into\s+languages\s+
    other\s+than\s+English\.\s*""",
    re.VERBOSE,
)


class State:
    def __init__(self, datatracker=None, verbose=0, default=True, width=79):
        self.datatracker = datatracker
        self.verbose = verbose
        self.width = width
        self.default = default


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], show_default=True)


@click.group(
    help="Review tool for IETF documents.", context_settings=CONTEXT_SETTINGS
)
@click.option(
    "--default-enable/--no-default-enable",
    "default",
    default=True,
    help="Whether all checks are enabled by default.",
)
@click.option(
    "--verbose",
    "-v",
    default=0,
    count=True,
    help="Be more verbose during operation.",
)
@click.option(
    "--datatracker",
    "-d",
    default="https://datatracker.ietf.org/",
    help="IETF Datatracker base URL.",
)
@click.option(
    "--width",
    "-w",
    default=79,
    help="Wrap the review to this character width.",
)
@click.pass_context
def cli(
    ctx: object, datatracker: str, verbose: int, default: bool, width: int
) -> None:
    datatracker = re.sub(r"/+$", "", datatracker)
    ctx.obj = State(datatracker, verbose, default, width)
    log.setLevel(logging.INFO if verbose == 0 else logging.DEBUG)

    cache = appdirs.user_cache_dir("ietf-reviewtool")
    if not os.path.isdir(cache):
        os.mkdir(cache)
    log.debug("Using cache directory %s", cache)
    requests_cache.install_cache(
        cache_name=os.path.join(cache, "ietf-reviewtool"),
        backend="sqlite",
        expire_after=datetime.timedelta(days=30),
    )


def die(msg: list, err: int = 1) -> None:
    """
    Print a message and exit with an error code.

    @param      msg   The message to print

    @return
    """
    log.error(msg)
    sys.exit(err)


def normalize_ws(string: str) -> str:
    """
    Replace multiple white space characters by a single space.

    @param      string  The string to replace in

    @return     The replacement string
    """
    return re.sub(r"\s+", r" ", string)


def word_join(words: list, oxford_comma=True, prefix="", suffix="") -> str:
    """
    Join list items using commas and "and", optionally each prefixed by
    something.

    @param      words         The words to join
    @param      oxford_comma  Whether to use the oxford comma
    @param      prefix        A prefix to use for each word
    @param      suffix        A suffix to use for each word

    @return     String of joined words
    """
    if len(words) == 0:
        return ""
    if len(words) == 1:
        return f"{prefix}{words[0]}{suffix}"
    if len(words) == 2:
        return f"{prefix}{words[0]}{suffix} and {prefix}{words[1]}{suffix}"
    return (
        f'{prefix}{f"{suffix}, {prefix}".join(words[:-1])}'
        f'{"," if oxford_comma else ""} and {prefix}{words[-1]}{suffix}'
    )


def fetch_url(url: str, use_cache: bool = True, method: str = "GET") -> str:
    """
    Fetches the resource at the given URL or checks its reachability (when
    method is "HEAD".) A failing HEAD request is retried as a GET, since some
    servers apparently don't like HEAD.

    @param      url        The URL to fetch
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


def read(file_name: str) -> str:
    """
    Read a file into a string.

    @param      file_name  The item to read

    @return     The content of the item.
    """
    try:
        with open(file_name, "rb") as file:
            return str(charset_normalizer.from_bytes(file.read()).best())
    except FileNotFoundError as err:
        log.error("%s -> %s", file_name, err)
        return None


def write(text: str, file_name: str) -> None:
    """
    Write a string into a file.

    @param      text       The text to write
    @param      file_name  The file name to write to

    @return     -
    """
    with open(file_name, "w") as file:
        file.write(text)


def unfold(text: str) -> str:
    """
    Unfolds the paragraphs (i.e., removes hard line ends) in a text string.

    @param      text  The text to unfold

    @return     The unfolded version of the text.
    """
    rand = r"bYYO2hxg2Bg4HhwEsbJQSSucukxfAbAIcDrPu5dw"

    folded = re.sub(r"[\r\f]", r"", text)
    folded = re.sub(r"\n{2,}\s*", rand, folded)
    folded = re.sub(r"^\s+", r"", folded, flags=re.MULTILINE)
    # folded = re.sub(
    #     r"([^a-z0-9])([a-z]{2,})://", r"\1\2://", folded, flags=re.IGNORECASE
    # )
    folded = re.sub(r"([\-/])\n([^\(])", r"\1\2", folded)
    folded = re.sub(r"\n", r" ", folded)
    folded = re.sub(rand, r"\n\n", folded)

    return folded


@click.command("extract-urls", help="Extract URLs from items.")
@click.argument("items", nargs=-1)
@click.option(
    "--include-example/--no-include-example",
    "examples",
    default=False,
    help="Include URLs for example domains, such as example.com.",
)
@click.option(
    "--include-common/--no-include-common",
    "common",
    default=True,
    help="Include URLs that are common in IETF documents "
    "(e.g., from the boilerplate).",
)
def extract_urls_from_items(
    items: list, examples: bool = False, common: bool = True
) -> None:
    urls = set()
    for item in items:
        if not os.path.isfile(item):
            log.warning("%s does not exist, skipping", item)
            continue

        log.debug("Extracting URLs from %s", item)
        text = strip_pagination(read(item))

        if text is not None:
            urls |= extract_urls(read(item), examples, common)

    for url in urls:
        print(url)


def extract_urls(
    text: str, examples: bool = False, common: bool = False
) -> set:
    """
    Return a list of URLs in a text string.

    @param      text      The text to extract URLs from
    @param      examples  Include example URLs
    @param      common    Include URLs that are common in IETF documents

    @return     List of URLs.
    """

    # find all URLs
    text = unfold(text)
    urls = []
    for url in re.findall(
        r"(?:[a-z]{2,})://(?:-\.)?(?:[^\s/?\.#)]+\.?)+(?:/[^\s)\">;]*)?",
        text,
        re.IGNORECASE,
    ):
        url = re.sub(r"(.*)[\"\']\s*\]\s*$", r"\1", url)
        url = url.rstrip(".\"'>;,")
        if not re.search(r"\[", url):
            url = url.rstrip("]")
        try:
            urllib.parse.urlparse(url).netloc
        except ValueError as err:
            log.warning("%s: %s", err, url)
            continue
        urls.append(url)

    if not examples:
        # remove example URLs
        urls = [
            u
            for u in urls
            if not re.search(
                r"example\.(?:com|net|org)|\.example$",
                urllib.parse.urlparse(u).netloc,
                re.IGNORECASE,
            )
        ]

    if not common:
        # remove some common URLs
        urls = [
            u
            for u in urls
            if not re.search(
                r"""https?://
                    datatracker\.ietf\.org/drafts/current/|
                    trustee\.ietf\.org/license-info|
                    (www\.)?rfc-editor\.org/info/rfc\d+|
                    (www\.)?ietf\.org/archive/id/draft-""",
                u,
                flags=re.VERBOSE | re.IGNORECASE,
            )
        ]

    return set(urls)


def get_current_agenda(datatracker: str) -> dict:
    """
    Download and the current IESG telechat agenda in JSON format.

    @param      datatracker  The datatracker URL to use

    @return     The current agenda as a dict.
    """
    agenda = fetch_url(
        datatracker + "/iesg/agenda/agenda.json", use_cache=False
    )
    if agenda is None:
        return {}
    return json.loads(agenda)


def get_items_on_agenda(agenda: dict) -> list:
    """
    Given an IESG telechat agenda dict, return the list of items that are on
    it.

    @param      agenda  An agenda dict

    @return     A list of the items on the given agenda.
    """
    items = []
    if "sections" in agenda:
        for _, sec in agenda["sections"].items():
            for doc_type in ["docs", "wgs"]:
                if doc_type in sec:
                    for doc in sec[doc_type]:
                        items.append(doc["docname"] + "-" + doc["rev"])
    return items


def strip_pagination(text: str) -> str:
    """
    Strip headers and footers, end-of-line whitespace and CR/LF, similar to the
    rfcstrip tool (https://trac.tools.ietf.org/tools/rfcstrip/) from which the
    regexs used below were originally adopted.

    @param      text  The text of an RFC or Internet-Draft

    @return     The stripped version of the text.
    """
    stripped = ""
    new_page = False
    sentence = False
    have_blank = False
    for num, line in enumerate(text.split("\n")):
        # FIXME: doesn't always leave a blank line after a figure caption
        mod = re.sub(r"\r", "", line)
        mod = re.sub(r"\s+$", "", mod)
        if re.search(r"\[?[Pp]age [\divx]+\]?[\s\f]*$", mod):
            continue
        if (
            re.search(r"^\s*\f", mod)
            or (
                num > 10
                and re.search(
                    r"^\s*I(nternet|NTERNET).D(raft|RAFT)\s{3,}.*$",
                    mod,
                )
            )
            or re.search(r"^\s*Draft.+[12]\d{3}\s*$", mod)
            or re.search(
                r"^(RFC.+\d+|draft-[-a-z\d_.]+.*\d{4})$",
                mod,
            )
            or re.search(
                r"""^\s*(RFC|Internet-Draft).*
                        (Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|
                        May|June?|July?|Aug(ust)?|Sep(tember)?|Oct(ober)?|
                        Nov(ember)?|Dec(ember)?)\s
                        (19[89]\d|20\d{2})\s*$""",
                mod,
                re.VERBOSE,
            )
        ):
            new_page = True
            continue
        if new_page and re.search(r"^\s*draft-[-a-z\d_.]+\s*$", line):
            continue
        if re.search(r"^\S", mod):
            sentence = True
        if re.search(r"\S", mod):
            if (new_page and sentence) or (not new_page and have_blank):
                stripped += "\n"
            have_blank = False
            sentence = False
            new_page = False
        if re.search(r"([.:?!]\s*|(https?|ftp)://\S+)$", mod):
            sentence = True
        if re.search(r"^\s*$", mod):
            have_blank = True
            continue
        stripped += mod + "\n"

    return stripped


def basename(item: str) -> str:
    """
    Return the base name of a given item by stripping the path, the version
    information and the txt suffix.

    @param      item  The item to return the base name for

    @return     The base name of the item
    """
    return re.sub(r"^(?:.*/)?(.*[^-]+)(-\d+)+(?:\.txt)?$", r"\1", item)


def fetch_dt(datatracker: str, query: str) -> dict:
    """
    Return dict of JSON query results from datatracker.

    @param      datatracker  The datatracker URL to use
    @param      query        The query to return data for

    @return     The query results.
    """
    api = "/api/v1/doc/"
    if not query.startswith(api):
        query = api + query
    if re.search(r"\?", query):
        query += "&format=json"
    else:
        query += "?format=json"
    content = fetch_url(datatracker + query)
    if content is not None:
        result = json.loads(content)
        return result["objects"] if "objects" in result else result
    return None


def get_latest(data: list, key: str) -> dict:
    """
    Gets the latest element, by timestamp in key, from data.

    @param      data  The list to return the latest element of
    @param      key   The timestamp key

    @return     The latest element by timestamp in data.
    """
    data.sort(
        key=lambda k: datetime.datetime.fromisoformat(k[key]),
        reverse=True,
    )
    return data[0]


def get_writeups(datatracker: str, item: str) -> str:
    """
    Download related document writeups for an item from the datatracker.

    @param      datatracker  The datatracker URL to use
    @param      item         The item to download write-ups for

    @return     The text of the writeup, if only a single one existed, else
                None.
    """
    doc_events = fetch_dt(
        datatracker, "writeupdocevent/?doc__name=" + basename(item)
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


@click.command("fetch", help="Download items (I-Ds, charters, RFCs, etc.)")
@click.argument("items", nargs=-1)
@click.option(
    "--strip/--no-strip",
    "strip",
    default=True,
    help="Strip headers, footers and pagination from downloaded items.",
)
@click.option(
    "--fetch-writeups/--no-fetch-writeups",
    "fetch_writeups",
    default=True,
    help="Fetch various write-ups related to the item.",
)
@click.pass_obj
def fetch(
    state: object, items: list, strip: bool, fetch_writeups: bool
) -> None:
    get_items(items, state.datatracker, strip, fetch_writeups)


def get_items(
    items: list, datatracker: str, strip: bool = True, get_writeup=False
) -> list:
    """
    Download named items into files of the same name in the current directory.
    Does not overwrite existing files. Names need to include the revision, and
    may or may not include the ".txt" suffix.

    @param      items        The items to download
    @param      datatracker  The datatracker URL to use
    @param      strip        Whether to run strip() on the downloaded item
    @param      get_writeup  Whether to download associated write-ups

    @return     List of file names written or existing
    """
    result = []
    for item in items:
        do_strip = strip
        file_name = item
        if not file_name.endswith(".txt"):
            file_name += ".txt"

        if get_writeup:
            get_writeups(datatracker, item)

        if os.path.isfile(file_name):
            log.warning("%s exists, skipping", file_name)
            result.append(file_name)
            continue

        log.debug("Getting %s", item)
        cache = None
        text = None
        url = None
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
            # TODO: the charters in rsync don't have milestones, can't use
            # cache = os.getenv("IETF_CHARTERS")
            do_strip = False
        elif item.startswith("conflict-review-"):
            doc = re.sub(r"conflict-review-(.*)", r"draft-\1", item)
            text = get_writeups(datatracker, doc)
            # TODO: in-progress conflict-reviews are not in the cache
            # cache = os.getenv("IETF_CONFLICT_REVIEWS")
            doc = basename(doc)
            target = fetch_dt(
                datatracker,
                "relateddocument/?relationship__slug=conflrev&target__name="
                + doc,
            )
            if not target:
                log.warning("cannot find target for %s", doc)
                continue
            docalias = fetch_dt(datatracker, target[0]["target"])
            if not docalias:
                log.warning("cannot find docalias for %s", target[0]["target"])
                continue
            doc = fetch_dt(datatracker, docalias["document"])
            if not doc:
                log.warning("cannot find doc for %s", docalias["document"])
                continue
            items.append(f"{doc['name']}-{doc['rev']}.txt")
            do_strip = False
        # else:
        #     die(f"Unknown item type: {item}")

        if cache is not None:
            cache_file = os.path.join(cache, file_name)
            if os.path.isfile(cache_file):
                log.debug("Using cached %s", item)
                text = read(cache_file)
            else:
                log.debug("No cached copy of %s in %s", item, cache)

        if text is None and url is not None:
            text = fetch_url(url)

        if text is not None:
            if do_strip:
                log.debug("Stripping %s", item)
                text = strip_pagination(text)
            write(text, file_name)
            result.append(file_name)

    return result


@click.command(
    "strip", help="Strip headers, footers and pagination from items."
)
@click.argument("items", nargs=-1)
@click.option(
    "--in-place/--no-in-place",
    "in_place",
    default=False,
    help="Overwrite original item with stripped version.",
)
def strip_items(items: list, in_place: bool = False) -> None:
    """
    Run strip_pagination over the named items.

    @param      items     The items to strip
    @param      in_place  Whether to overwrite the item, or save a ".stripped"
                          copy.

    @return     -
    """
    for item in items:
        if not os.path.isfile(item):
            log.warning("%s does not exist, skipping", item)
            continue

        text = strip_pagination(read(item))

        if text is not None:
            if not in_place:
                item += ".stripped"
                if os.path.isfile(item):
                    log.warning("%s exists, skipping", item)
                    continue

            log.debug("Saving stripped version as %s", item)
            write(text, item)


def section_and_paragraph(
    nxt: str, cur: str, para_sec: list, is_diff: bool = True
) -> list:
    """
    Return a list consisting of the current paragraph number and section title,
    based on the next and current lines of text and the current paragraph
    number and section title list.

    @param      nxt       The next line in the diff
    @param      cur       The current line in the diff
    @param      para_sec  The current (paragraph number, section name) list

    @return     An updated (paragraph number, section name) list.
    """
    [para, sec, had_nn] = (
        para_sec if para_sec is not None else [1, None, False]
    )

    # track paragraphs
    pat = {True: r"^[\- ] +$", False: r"^\s*$"}
    if re.search(pat[is_diff], cur):
        para += 1

    # track sections
    pot_sec = SECTION_PATTERN.search(cur)
    pat = {True: r"^([\- ] +$|\+ )", False: r"^( *$)"}
    if pot_sec and nxt and (re.search(pat[is_diff], nxt) or len(cur) > 65):
        pot_sec = pot_sec.group(1)
        if re.match(r"\d", pot_sec):
            if had_nn:
                para = 1
                sec = (
                    "Section " + re.sub(r"(.*)\.$", r"\1", pot_sec)
                    if re.match(r"\d", pot_sec)
                    else f'"{pot_sec}"'
                )
        else:
            para = 1
            had_nn = True
            sec = '"' + pot_sec + '"'

    return [para, sec, had_nn]


def fmt_section_and_paragraph(para_sec: list, cat: str) -> str:
    """
    Return a formatted prefix line indicating the current section name,
    paragraph number, and category.

    @param      para_sec  The current (paragraph number, section name) list
    @param      cat       The category to indicate

    @return     A formatted prefix line.
    """
    para_sec = para_sec if para_sec else [1, None, False]
    line = f"{para_sec[1]}, p" if para_sec[1] else "P"
    line += f"aragraph {para_sec[0]}, {cat}:\n"
    return line


def fmt_nit(changed: list, indicator: list, para_sec: list) -> list:
    """
    Format a nit.

    @param      changed    Changed lines
    @param      indicator  Indicator lines
    @param      para_sec   The current (paragraph number, section name) list

    @return     The formatted nit.
    """
    result = [fmt_section_and_paragraph(para_sec, "nit")]
    for prefix in ["-", "+"]:
        for tup in zip(changed[prefix], indicator[prefix]):
            # add the changed line followed by an indicator line
            result.append(tup[0])
            if tup[1]:
                result.append(tup[1].replace("?", prefix, 1))
        indicator[prefix].clear()
        changed[prefix].clear()
    result.append("\n")
    return result


def gather_nits(diff: list) -> list:
    """
    Return a list of prefixed nits from the current diff.

    @param      diff  The diff to extract nits from

    @return     A list of prefixed nits.
    """
    changed = {"+": [], "-": []}
    indicator = {"+": [], "-": []}
    para_sec = None
    prev = None
    result = []

    for num, cur in enumerate(diff):
        kind = cur[0]

        if cur in ["+ \n", "- \n"]:
            prev = kind
            continue

        nxt = diff[num + 1] if num < len(diff) - 1 else None
        nxt_kind = nxt[0] if nxt else None

        if kind in ["+", "-"] and nxt_kind == "?":
            changed[kind].append(cur)

        elif kind == "?" and prev in ["+", "-"]:
            indicator[prev].append(cur)

        elif kind in ["+", "-"] and prev == "?":
            changed[kind].append(cur)
            indicator[kind].append(None)

        elif kind == "-" and nxt_kind == "+":
            changed[kind].append(cur)
            indicator[kind].append(None)

        elif kind == "+" and prev == "-":
            changed[kind].append(cur)
            indicator[kind].append(None)

        elif changed["-"] or changed["+"]:
            result.extend(fmt_nit(changed, indicator, para_sec))

        if nxt:
            para_sec = section_and_paragraph(nxt, cur, para_sec)

        prev = kind

    if changed["-"] or changed["+"]:
        result.extend(fmt_nit(changed, indicator, para_sec))

    return result


def strip_nits_from_diff(diff: list) -> list:
    """
    Return a version of the passed diff with all lines related to nits removed.

    @param      diff  The diff to strip nits from

    @return     A diff with all nits removed.
    """
    prev = None
    continue_again = False
    result = []

    for num, cur in enumerate(diff):
        if continue_again:
            continue_again = False
            continue

        kind = cur[0]

        if cur in ["+ \n", "- \n"]:
            prev = kind
            continue

        nxt = diff[num + 1] if num < len(diff) - 1 else None
        nxt_kind = nxt[0] if nxt else None

        if kind == "+":
            if nxt_kind == "?":
                continue_again = True
                prev = kind
                continue
            if prev == "?":
                prev = kind
                continue

        if kind == "?" and prev in ["+", "-"]:
            prev = kind
            continue

        if kind == "-":
            cur = re.sub(r".(.*)", r" \1", cur)

        result.append(cur)
        prev = kind
    return result


def fmt_comment(item: dict, para_sec: list) -> list:
    """
    Format a comment.

    @param      item      The comment item dict
    @param      para_sec  The current (paragraph number, section name) list

    @return     The formatted comment.
    """
    result = [fmt_section_and_paragraph(para_sec, item["cat"])]
    result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
    if item["ctx"]:
        result.append("\n")
    result.extend([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])
    if item["txt"]:
        result.append("\n")
    if item["ctx"]:
        para_sec[0] -= 1  # don't count this as a paragraph
    item.clear()
    return result


def gather_comments(diff: list) -> dict:
    """
    Return a dict that contains lists of all comments of all categories.

    @param      diff  A diff with nits removed (by strip_nits_from_diff)

    @return     A review dict.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    para_sec = None
    item = {}

    for num, cur in enumerate(diff):
        nxt = diff[num + 1] if num < len(diff) - 1 else None

        start = re.search(r"^\+ (?:(DISCUSS|COMMENT|NIT):?)?\s*(.*)", cur)
        if start and start.group(1):
            if "cat" in item:
                result[item["cat"]].extend(fmt_comment(item, para_sec))
            item["cat"] = start.group(1).lower()
            item["ctx"] = []
            item["ctx_ok"] = start.group(2) != ""
            item["txt"] = []
            item["txt_ok"] = False
            if item["ctx_ok"]:
                cur = "+ " + start.group(2) + "\n"
            else:
                continue

        if "txt_ok" in item:
            kind = cur[0]
            if item["ctx_ok"] is False:
                if kind != " ":
                    item["txt"].append(cur)
                    item["ctx_ok"] = True
                else:
                    item["ctx"].append(cur)
            else:
                if kind != "+":
                    item["txt_ok"] = True
                else:
                    item["txt"].append(cur)

            if item["txt_ok"] or nxt is None:
                result[item["cat"]].extend(fmt_comment(item, para_sec))

        para_sec = section_and_paragraph(nxt, cur, para_sec)

    return result


def review_item(orig: list, rev: list) -> dict:
    """
    Calculates a diff between orig and rev.

    @param      orig  The original text
    @param      rev   The revised text

    @return     A diff between orig and rev.
    """

    # difflib can't deal with single lines it seems
    if len(orig) == 1:
        orig.append("\n")
    if len(rev) == 1:
        rev.append("\n")

    diff = list(difflib.ndiff(orig, rev, linejunk=None, charjunk=None))

    nits = gather_nits(diff)
    diff = strip_nits_from_diff(diff)
    review = gather_comments(diff)
    review["nit"].extend(nits)
    return review


def wrap_para(text: str, width: int = 79, end: str = "\n\n"):
    """
    Return a wrapped version of the text, ending with end.

    @param      text   The text to wrap
    @param      width  The width to wrap to
    @param      end    The end to add to the text

    @return     Wrapped version of text followed by end.
    """
    return textwrap.fill(text, width=width, break_on_hyphens=False) + end


def bulletize(text: str, width: int = 79, end: str = "\n\n"):
    """
    Return a wrapped version of the text, ending with end, as a bullet item.

    @param      text   The text to wrap
    @param      width  The width to wrap to
    @param      end    The end to add to the text

    @return     Wrapped version of text followed by end, formatted as bullet
                item.
    """
    return textwrap.indent(
        wrap_para(" * " + text, width - 3, end),
        "   ",
        lambda line: not line.startswith(" * "),
    )


def fmt_review(review: dict, width: int) -> None:
    """
    Format a review dict for datatracker submission.

    @param      review  The review to format
    @param      width   The column number to wrap the review to

    @return     Wrapped text version of the review.
    """
    boilerplate = {
        "discuss": None,
        "comment": None,
        "nit": (
            "All comments below are about very minor potential issues "
            "that you may choose to address in some way - or ignore - "
            "as you see fit. Some were flagged by automated tools (via "
            "https://github.com/larseggert/ietf-reviewtool), so there "
            "will likely be some false positives. "
            "There is no need to let me know what you did "
            "with these suggestions."
        ),
    }

    used_categories = 0
    for category in boilerplate:
        if review[category]:
            used_categories += 1

    for category in boilerplate:
        if not review[category]:
            continue

        if used_categories > 1:
            print("-" * width)
            print(category.upper())
            print("-" * width)

        if boilerplate[category]:
            print(wrap_para(boilerplate[category], width=width, end="\n"))

        for line in review[category]:
            print(line, end="")


def extract_abstract(text: list) -> str:
    """
    Return that abstract of the text .

    @param      text  The text to parse for the abstract

    @return     The abstract.
    """
    in_abstract = False
    abstract = ""
    for line in text.splitlines(keepends=True):
        pot_sec = SECTION_PATTERN.search(line)
        if pot_sec:
            which = pot_sec.group(0)
            if re.search(r"^Abstract", which):
                in_abstract = True
                continue
            if abstract:
                break
        if in_abstract:
            abstract += line
    return abstract


def extract_refs(text: list) -> dict:
    """
    Return a dict of references found in the text as well as the normative and
    informative reference sections.

    @param      text  The text to parse for references

    @return     A dict with sets of found references.
    """
    parts = {"text": "", "informative": "", "normative": ""}
    part = "text"
    for line in text.splitlines(keepends=True):
        pot_sec = SECTION_PATTERN.search(line)
        if pot_sec:
            which = pot_sec.group(0)
            if re.search(
                r"^(\d\.?)+\s+Informative\s+References?", which, re.IGNORECASE
            ):
                part = "informative"
            elif re.search(
                r"^(\d\.?)+\s+(Normative\s+)?References?", which, re.IGNORECASE
            ):
                part = "normative"
            else:
                part = "text"
        parts[part] += line

    refs = {}
    for part in parts:
        refs[part] = re.findall(
            r"(\[(?:\d+|[a-z]+(?:[-_.]?\w+)*)\]"
            + (r"|RFC\d+|draft-[-a-z\d_.]+" if part == "text" else r"")
            + r")",
            unfold(parts[part]),
            re.IGNORECASE,
        )
        refs[part] = {f"[{untag(ref)}]" for ref in refs[part]}

    resolved = {}
    for part in ["informative", "normative"]:
        resolved[part] = []
        for ref in refs[part]:
            ref_text = re.search(
                r"\s*" + re.escape(ref) + r"\s+((?:[^\n][\n]?)+)\n",
                parts[part],
                re.DOTALL,
            )
            if ref_text:
                ref_text = unfold(ref_text.group(0))
                found = False

                for pat in [r"(draft-[-a-z\d_.]+)", r"((?:RFC|rfc)\d+)"]:
                    match = re.search(pat, ref_text)
                    if match:
                        found = True
                        resolved[part].append((ref, match.group(0).lower()))
                        break

                if not found:
                    urls = extract_urls(ref_text, True, True)
                    resolved[part].append((ref, urls.pop() if urls else None))

    resolved["text"] = refs["text"]
    return resolved


def duplicates(data: list) -> set:
    """
    Return duplicate elements in a list.

    @param      data  The list to locate duplicates in

    @return     Duplicate elements of data.
    """
    seen = {}
    dupes = set()
    for item in data:
        if item not in seen:
            seen[item] = 1
        else:
            if seen[item] == 1:
                dupes.add(item)
            seen[item] += 1
    return dupes.discard(None)


def is_downref(level: str, kind: str, ref_level: str) -> bool:
    """
    Check if a document reference is allowed (i.e., is not a DOWNREF) for a
    document at a given standards level.

    @param      level      The (intended) standards level of the given document
    @param      kind       The kind of reference (normative or informative.)
    @param      ref_level  The status level of the reference

    @return     True if this is a DOWNREF, True otherwise.
    """
    if kind.lower() == "normative":
        rank = {
            "internet standard": 3,
            "full standard": 3,
            "best current practice": 3,
            "draft standard": 2,
            "proposed standard": 1,
            "standards track": 1,
            "experimental": 0,
            "informational": 0,
            "unknown": 0,
        }
        return rank[level.lower()] > rank[ref_level.lower()]
    if kind.lower() == "informative":
        return False
    die(f"unknown kind {kind}")


def fetch_downrefs(datatracker: str) -> list:
    """
    Fetches DOWNREFs from datatracker and returns them as a list.

    @param      datatracker  The datatracker URL to use

    @return     A list of RFC names.
    """
    downrefs = fetch_dt(
        datatracker, "relateddocument/?relationship=downref-approval&limit=0"
    )
    return [re.sub(r".*(rfc\d+).*", r"\1", d["target"]) for d in downrefs]


def untag(tag: str) -> str:
    """
    Remove angle brackets from reference tag.

    @param      tag   Reference tag

    @return     Tag without angle brackets.
    """
    return re.sub(r"^\[(.*)\]$", r"\1", tag)


def wrap_and_indent(text: str, width: int = 50) -> str:
    """
    Wrap and indent a string if it is longer than width characters.

    @param      text   The text to wrap and indent
    @param      width  The width to wrap to

    @return     Wrapped and indented text, or original text.
    """
    return (
        "\n"
        + textwrap.indent(
            textwrap.fill(text, width=width - 5, break_on_hyphens=False),
            "     ",
        )
        if len(text) > 50
        else text
    )


def check_inclusivity(text: str, width: int, verbose: bool = False) -> dict:
    """
    Check document terminology for potential inclusivity issues.

    @param      text   The document text
    @param      width  The width the issues should be wrapped to

    @return     List of possible inclusivity issues.
    """
    review = {"discuss": [], "comment": [], "nit": []}
    isb_url = (
        "https://raw.githubusercontent.com/"
        "NTAP/isb-ietf-config/main/.github/in-solidarity.yml"
    )
    isb_yaml = fetch_url(isb_url)

    if not isb_yaml:
        log.info("Could not fetch in-solidarity.yml from %s", isb_url)
        return review
    rules = yaml.safe_load(isb_yaml)

    result = {}
    for name, data in rules["rules"].items():
        for pattern in data["regex"]:
            pattern = re.sub(r"/(.*)/.*", r"((\1)\\w*)", pattern)
            hits = re.findall(pattern, text, re.IGNORECASE)
            if hits:
                result[name] = (
                    list(filter(None, set(itertools.chain(*hits)))),
                    pattern,
                    data["alternatives"] if "alternatives" in data else None,
                )

    if result:
        review["comment"].append(
            wrap_para(
                "Found terminology that should be reviewed for inclusivity; "
                "see https://www.rfc-editor.org/part2/#inclusive_language "
                "for background and more guidance:",
                width=width,
                end="\n\n",
            )
        )
        for name, match in result.items():
            terms = word_join(match[0], prefix='"', suffix='"')
            msg = f'Term{"s" if len(match[0]) > 1 else ""} {terms}; '
            if match[2]:
                msg += "alternatives might be "
                msg += ", ".join([f'"{a}"' for a in match[2]])
            else:
                msg += "but I have no suggestion for an alternative"
            if verbose:
                msg += f' (matched "{name}" rule, pattern {match[1]})'
            review["comment"].extend(bulletize(msg, width=width, end=".\n\n"))

    return review


def check_refs(
    datatracker: str,
    refs: dict,
    rels: dict,
    width: int,
    name: str,
    status: str,
    meta: dict,
    text: str,
) -> dict:
    """
    Check the references.

    @param      datatracker  The datatracker URL to use
    @param      refs         The references to check
    @param      rels         The relationship of this document to others
    @param      width        The width to wrap to
    @param      name         The name of this document.
    @param      status       The standards level of the given document
    @param      meta         The metadata
    @param      text         The document text

    @return     List of messages.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    downrefs = fetch_downrefs(datatracker)

    # remove self-mentions from extracted references in the text
    refs["text"] = [r for r in refs["text"] if not untag(r).startswith(name)]

    # check for duplicates
    for kind in ["normative", "informative"]:
        if not refs[kind]:
            continue
        tags, tgts = zip(*refs[kind])
        dupes = duplicates(tags)
        if dupes:
            result["nit"].append(
                wrap_para(
                    f"Duplicate {kind} references: {word_join(dupes)}.",
                    width=width,
                )
            )

        dupes = duplicates(tgts)
        if dupes:
            tags = [t[0] for t in refs[kind] if t[1] in dupes]
            result["nit"].append(
                wrap_para(
                    f"Duplicate {kind} references to: {word_join(dupes)}.",
                    width=width,
                )
            )

    norm = set(e[0] for e in refs["normative"])
    info = set(e[0] for e in refs["informative"])
    both = norm | info
    in_text = {"[" + r + "]" for r in {untag(r) for r in refs["text"]}}

    if norm & info:
        result["nit"].append(
            wrap_para(
                "Reference entries duplicated in both normative and "
                f"informative sections: {word_join(list(norm & info))}.",
                width=width,
            )
        )

    if in_text - both:
        ref_list = wrap_and_indent(
            word_join(list(in_text - both)), width=width
        )
        result["comment"].append(
            f"No reference entries found for: {ref_list}\n\n"
        )

    if both - in_text:
        ref_list = wrap_and_indent(
            word_join(list(both - in_text)), width=width
        )
        result["nit"].append(f"Uncited references: {ref_list}\n\n")

    for rel, docs in rels.items():
        for doc in docs:
            ref = f"rfc{doc}"
            in_normative = ref in [x[1] for x in refs["normative"]]
            in_informative = ref in [x[1] for x in refs["informative"]]

            if not in_normative and not in_informative:
                result["comment"].append(
                    wrap_para(
                        f"Document {rel} RFC{doc}, but does not cite it as a "
                        f"reference.",
                        width=width,
                    )
                )

    level = meta and (meta["std_level"] or meta["intended_std_level"])
    if not level:
        # if we have no level from the metadata, see if the document has one
        level = re.search(r"^Intended status: (.*)\s{2,}", text, re.MULTILINE)
        level = level[1].rstrip() if level else "unknown"

    for kind in ["normative", "informative"]:
        for tag, doc in refs[kind]:
            if doc:
                name = re.search(r"^(rfc\d+|draft-[-a-z\d_.]+)", doc)
            if not doc or not name:
                log.info(
                    "No metadata available for %s reference %s (%s)",
                    kind,
                    tag,
                    name,
                )
                if kind == "normative":
                    result["comment"].append(
                        wrap_para(
                            f"Possible DOWNREF from this {status} doc "
                            f"to {tag}. If so, the IESG needs to approve it.",
                            width=width,
                        )
                    )
                continue

            draft_components = re.search(
                r"^(draft-.*)-(\d{2,})$", name.group(0)
            )
            rev = None
            if draft_components:
                name = draft_components.group(1)
                rev = draft_components.group(2)
            else:
                name = re.sub(r"rfc0*(\d+)", r"rfc\1", name.group(0))
            ref_meta = fetch_meta(datatracker, basename(name))
            display_name = re.sub(r"rfc", r"RFC", name)

            latest = ref_meta and get_latest(
                ref_meta["rev_history"], "published"
            )
            if latest["rev"] and rev and latest["rev"] > rev:
                if latest["rev"].startswith("rfc"):
                    result["nit"].append(
                        wrap_para(
                            f"Document references {display_name}, but that "
                            f"has been published as {latest['rev'].upper()}.",
                            width=width,
                        )
                    )
                else:
                    result["nit"].append(
                        wrap_para(
                            f"Document references {name}-{rev}, but "
                            f"-{latest['rev']} is the latest "
                            f"available revision.",
                            width=width,
                        )
                    )

            if status.lower() not in ["informational", "experimental"]:
                ref_level = (
                    ref_meta["std_level"]
                    or ref_meta["intended_std_level"]
                    or "unknown"
                )
                if is_downref(level, kind, ref_level) and name not in downrefs:
                    if ref_level is None:
                        result["comment"].append(
                            wrap_para(
                                f"Possible DOWNREF {tag} from this {level} "
                                f"to {display_name}.",
                                width=width,
                            )
                        )
                    else:
                        result["discuss"].append(
                            wrap_para(
                                f"DOWNREF {tag} from this {level} to "
                                f"{ref_level} {display_name}.",
                                width=width,
                            )
                        )

            obsoleted_by = fetch_dt(
                datatracker,
                "relateddocument/?relationship__slug=obs&target__name=" + name,
            )
            if obsoleted_by:
                ob_bys = []
                for o in obsoleted_by:
                    obs_by = fetch_dt(datatracker, o["source"])
                    if "rfc" in obs_by:
                        ob_bys.append(obs_by["rfc"])

                ob_rfcs = word_join(ob_bys, prefix="RFC")
                result["nit"].append(
                    wrap_para(
                        f"Reference {tag} to {display_name}, "
                        f"which was obsoleted by {ob_rfcs} "
                        f"(this may be on purpose).",
                        width=width,
                    )
                )

    return result


def get_status(doc: str) -> str:
    """
    Extract the standards level status of a given document.

    @param      doc   The document to extract the level from

    @return     The status of the document.
    """
    status = re.search(
        r"^(?:[Ii]ntended )?[Ss]tatus:\s*((?:\w+\s)+)",
        doc,
        re.MULTILINE,
    )
    return status.group(1).strip() if status else ""


def fetch_meta(datatracker: str, doc: str) -> dict:
    """
    Fetches metadata for doc from datatracker.

    @param      datatracker  The datatracker URL to use
    @param      doc          The document to fetch metadata for

    @return     The metadata, or None
    """
    url = datatracker + "/doc/" + doc + "/doc.json"
    meta = fetch_url(url)
    if not meta:
        log.info("No metadata available for %s", doc)
        return None
    return json.loads(meta)


def get_relationships(
    doc: str,
) -> dict:
    """
    Extract the documents that are intended to be updated by this document.

    @param      doc   The document to extract the information from

    @return     A list of documents
    """
    result = {}
    pat = {"updates": r"[Uu]pdates", "obsoletes": r"[Oo]bsoletes"}
    for rel in ["updates", "obsoletes"]:
        match = re.search(
            r"^"
            + pat[rel]
            + r":\s*((?:(?:RFC\s*)?\d{3,},?\s*)+)"
            + r"(?:.*[\n\r\s]+((?:(?:RFC\s*)?\d{3,},?\s*)+)?)?",
            doc,
            re.MULTILINE,
        )
        if match:
            result[rel] = "".join([group for group in match.groups() if group])
            result[rel] = re.sub(r"[,\s]+(\w)", r",\1", result[rel])
            result[rel] = result[rel].strip().split(",")
    return result


def check_xml(doc: str) -> None:
    """
    Check any XML in the document for issues

    @param      doc   The document text

    @return     List of issues found
    """
    snippets = re.finditer(r"^(.*)<\?xml\s", doc, re.MULTILINE)
    for snip in snippets:
        start = re.search(r"<\s*(\w+)", doc[snip.start() :])
        if not start:
            log.warning("cannot find an XML start tag")
            continue

        end = re.search(
            r"</\s*" + re.escape(start.group(1)) + r"\s*>", doc[snip.start() :]
        )
        if not end:
            log.warning('cannot find XML end tag "%s"', start.group(1))
            continue

        text = doc[snip.start() : snip.start() + end.end()]
        if snip.group(1):
            prefix = snip.group(1)
            # log.debug('XML prefix "%s"', prefix)
            text = re.sub(
                r"^" + re.escape(prefix), r"", text, flags=re.MULTILINE
            )

        # TODO: reflect XML error in review (once there is a test case)
        xml.etree.ElementTree.fromstring(text)


def check_grammar(
    review: str,
    grammar_skip_rules: str,
    width: int,
    show_rule_id: bool = False,
) -> dict:
    """
    Check document grammar.

    @param      review  The document text
    @param      width   The width the issues should be wrapped to

    @return     List of grammar nits
    """
    issues = [
        i
        for i in language_tool_python.LanguageTool("en").check(
            unfold("".join(review))
        )
        if i.ruleId
        not in [
            "ADVERTISEMENT_OF_FOR",
            "ALL_OF_THE",
            "ARROWS",
            "BOTH_AS_WELL_AS",
            "COMMA_COMPOUND_SENTENCE",
            "COMMA_PARENTHESIS_WHITESPACE",
            "COPYRIGHT",
            "CURRENCY",
            "DASH_RULE",
            "DATE_FUTURE_VERB_PAST",
            "EN_QUOTES",
            "EN_UNPAIRED_BRACKETS",
            "ENGLISH_WORD_REPEAT_BEGINNING_RULE",
            "HYPOTHESIS_TYPOGRAPHY",
            "I_LOWERCASE",
            "IN_THE_INTERNET",
            "INCORRECT_POSSESSIVE_FORM_AFTER_A_NUMBER",
            "KEY_WORDS",
            "LARGE_NUMBER_OF",
            "MULTIPLICATION_SIGN",
            "PLUS_MINUS",
            "PUNCTUATION_PARAGRAPH_END",
            "RETURN_IN_THE",
            "SENTENCE_WHITESPACE",
            "SO_AS_TO",
            "SOME_OF_THE",
            "UNIT_SPACE",
            "UPPERCASE_SENTENCE_START",
            "WHITESPACE_RULE",
            "WORD_CONTAINS_UNDERSCORE",
        ]
        and (
            not grammar_skip_rules
            or i.ruleId not in grammar_skip_rules.split(",")
        )
    ]

    para_sec = None
    cur = 0
    pos = 0
    result = {"discuss": [], "comment": [], "nit": []}
    for issue in issues:
        while pos + len(review[cur + 1]) < issue.offset:
            para_sec = section_and_paragraph(
                review[cur + 1], review[cur], para_sec, is_diff=False
            )
            pos += len(review[cur])
            cur += 1

        result["nit"].append(fmt_section_and_paragraph(para_sec, "nit"))
        context = issue.context.lstrip(".")
        offset = issue.offsetInContext - (len(issue.context) - len(context))
        context = context.rstrip(".")

        compressed = re.sub(r"\s+", r" ", context[0:offset])
        offset -= len(context[0:offset]) - len(compressed)
        context = re.sub(r"\s+", r" ", context)

        if len(context) > width - 2:
            cut = math.ceil((len(context) - width + 2) / 2)
            context = context[cut:-cut]
            offset -= cut

        result["nit"].append("> " + context + "\n")
        result["nit"].append(
            "> " + " " * offset + "^" * issue.errorLength + "\n"
        )

        message = (
            issue.message.replace("“", '"')
            .replace("’s", "'s")
            .replace("n’t", "n't")
            .replace("”", '"')
            .replace("‘", '"')
            .replace("’", '"')
        )

        if not re.search(r".*[.!?]$", message):
            message += "."

        if show_rule_id:
            message = f"{message} [{issue.ruleId}]"

        result["nit"].append(wrap_para(f"{message}", width=width))

    return result


def relationship_ok(status: str, level: str) -> bool:
    """
    Check if a document with the given intended status can have a relationship
    with a document of the given level.

    @param      status  The intended status of a document
    @param      level   The level of a document

    @return     True if the relationship is OK.
    """
    std = [
        "standards track",
        "best current practice",
        "proposed standard",
        "draft standard",
        "internet standard",
    ]
    return (status.lower() in std) or (level.lower() not in std)


def check_meta(datatracker: str, text: str, meta: dict, width: int) -> dict:
    """
    Check document metadata for issues.

    @param      text   The text of the document
    @param      meta   The metadata
    @param      width  The width the comments should be wrapped to

    @return     List of issues found
    """
    result = {"discuss": [], "comment": [], "nit": []}

    level = meta["std_level"] or meta["intended_std_level"]
    if not level:
        result["discuss"].append(
            wrap_para(
                "Datatracker does not record an intended RFC status "
                "for this document.",
                width=width,
            )
        )
    else:
        status = get_status(text)
        if status != level and (
            level != "Proposed Standard" or status != "Standards Track"
        ):
            result["discuss"].append(
                wrap_para(
                    f'Intended RFC status in datatracker is "{level}", but '
                    f'document says "{status}".',
                    width=width,
                )
            )

    num_authors = len(meta["authors"])
    if num_authors > 5:
        result["comment"].append(
            wrap_para(
                f"The document has {num_authors} authors, which exceeds the "
                "recommended author limit. I assume the sponsoring AD has "
                "agreed that this is appropriate?",
                width=width,
            )
        )

    iana_review_state = (
        meta["iana_review_state"] if "iana_review_state" in meta else None
    )
    if iana_review_state:
        if re.match(r".*Not\s+OK", iana_review_state, re.IGNORECASE):
            result["comment"].append(
                wrap_para(
                    "This document seems to have unresolved IANA issues.",
                    width=width,
                )
            )
        elif re.match(r".*Review\s+Needed", iana_review_state, re.IGNORECASE):
            result["comment"].append(
                wrap_para(
                    "The IANA review of this document seems to not have "
                    "concluded yet.",
                    width=width,
                )
            )
    else:
        log.warning("No IANA review state?")

    consensus = meta["consensus"] if "consensus" in meta else None
    if not consensus:
        result["comment"].append(
            wrap_para(
                "There does not seem to be consensus for this document.",
                width=width,
            )
        )

    stream = meta["stream"] if "stream" in meta else None
    if stream != "IETF":
        result["comment"].append(
            wrap_para(
                "This does not seem to be an IETF-stream document.",
                width=width,
            )
        )

    status = get_status(text)
    for rel, docs in get_relationships(text).items():
        if rel == "updates":
            abstract = extract_abstract(text)
            if not re.search(r"updates", abstract):
                updates = word_join(docs, prefix="RFC")
                result["discuss"].append(
                    wrap_para(
                        f"This document updates {updates}, but does not seem "
                        f"to include explanatory text about this in the "
                        f"abstract.",
                        width=width,
                    )
                )

        for doc in docs:
            meta = fetch_meta(datatracker, "rfc" + doc)
            level = meta["std_level"] or meta["intended_std_level"]
            if not relationship_ok(status, level):
                result["discuss"].append(
                    wrap_para(
                        f"This {status} document {rel} RFC{doc}, "
                        f"which is {level}.",
                        width=width,
                    )
                )

    return result


def check_tlp(text: str, status: str, width: int) -> dict:
    """
    Check the boilerplate against the Trust Legal Provisions (TLP).

    @param      text    The document text
    @param      status  The standards level of this document
    @param      width   The width the comments should be wrapped to

    @return     List of issues found.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    text = unfold(text)
    if re.search(
        r"""This\s+document\s+may\s+not\s+be\s+modified,?\s+and\s+derivative\s+
            works\s+of\s+it\s+may\s+not\s+be\s+created""",
        text,
        re.VERBOSE,
    ):
        msg = (
            "Document has an IETF Trust Provisions (TLP) Section 6.c(i) "
            "Publication Limitation clause. This means it can in most cases"
            "not be a WG document."
        )
        if status.lower() == "standards track":
            msg += " And it cannot be published on the Standards Track."
        result["discuss"].append(wrap_para(msg, width=width))

    return result


def check_boilerplate(text: str, status: str, width: int) -> dict:
    """
    Check the RFC2119/RFC8174 boilerplate in the document.

    @param      text    The document text
    @param      status  The standards level of this document
    @param      width   The width the comments should be wrapped to

    @return     List of issues found.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    uses_keywords = set(re.findall(KEYWORDS_PATTERN, text))
    has_8174_boilerplate = set(re.findall(BOILERPLATE_8174_PATTERN, text))
    has_2119_boilerplate = set(re.findall(BOILERPLATE_2119_PATTERN, text))
    has_boilerplate_begin = set(re.findall(BOILERPLATE_BEGIN_PATTERN, text))

    msg = None
    if uses_keywords:
        used_keywords = []
        for word in set(uses_keywords):
            used_keywords.append(normalize_ws(word))
        used_keywords = word_join(used_keywords, prefix='"', suffix='"')
        kw_text = f"keyword{'s' if len(uses_keywords) > 1 else ''}"
        if status.lower() in ["informational", "experimental"]:
            result["comment"].append(
                wrap_para(
                    f"Document has {status} status, but uses the RFC2119 "
                    f"{kw_text} {used_keywords}.",
                    width=width,
                )
            )

        if not has_8174_boilerplate:
            msg = (
                f"This document uses the RFC2119 {kw_text} {used_keywords}, "
                f"but does not contain the recommended RFC8174 boilerplate."
            )
            if has_2119_boilerplate:
                msg += " (It contains a variant of the RFC2119 boilerplate.)"
            elif has_boilerplate_begin:
                msg += " (It contains some text with a similar beginning.)"
    else:
        if (
            has_8174_boilerplate
            or has_2119_boilerplate
            or has_boilerplate_begin
        ):
            msg = "This document does not use RFC2119 keywords, but contains"
            if has_8174_boilerplate:
                msg += "the RFC8174 boilerplate."
            elif has_2119_boilerplate:
                msg += "the RFC2119 boilerplate."
            elif has_boilerplate_begin:
                msg += (
                    "text with a beginning similar to the RFC2119 boilerplate."
                )

    if msg:
        result["comment"].append(wrap_para(msg, width=width))

    if uses_keywords:
        lc_not = set(re.findall(LC_NOT_KEYWORDS_PATTERN, text))
        if lc_not:
            lc_not_str = word_join(list(lc_not), prefix='"', suffix='"')
            result["comment"].append(
                wrap_para(
                    f'Using lowercase "not" together with an uppercase '
                    f"RFC2119 keyword is not acceptable usage. Found: "
                    f"{lc_not_str}",
                    width=width,
                )
            )

    sotm = ""
    for line in text.splitlines(keepends=True):
        if re.match(r"^\s+$", line):
            continue
        if len(sotm) == 0:
            if re.match(
                r"^\s*Status\s+of\s+This\s+Memo\s*$", line, re.IGNORECASE
            ):
                sotm += " "
            continue
        if re.match(r"^\s*Copyright Notice\s*$", line):
            continue
        if re.match(r"^\s*Table\s+of\s+Contents\s*$", line, re.IGNORECASE):
            break
        sotm += line
    sotm = unfold(sotm)

    if re.search(TLP_6A_PATTERN, sotm):
        sotm = re.sub(TLP_6A_PATTERN, r"", sotm)
    else:
        result["comment"].append(
            wrap_para(
                'TLP Section 6.a "Submission Compliance for '
                'Internet-Drafts" boilerplate text seems to have issues.',
                width=width,
            )
        )

    idg_issues = False

    for required, pat in ID_GUIDELINES_PATTERNS:
        if re.search(pat, sotm):
            sotm = re.sub(pat, r"", sotm)
        elif required:
            idg_issues = True
    if idg_issues:
        result["comment"].append(
            wrap_para(
                "I-D Guidelines boilerplate text seems to have issues.",
                width=width,
            )
        )

    if re.search(COPYRIGHT_IETF, sotm):
        sotm = re.sub(COPYRIGHT_IETF, r"", sotm)
    elif re.search(COPYRIGHT_ALT_STREAMS, sotm):
        sotm = re.sub(COPYRIGHT_ALT_STREAMS, r"", sotm)
        result["comment"].append(
            wrap_para(
                'Document contains a TLP Section 6.b.ii "alternate streams" '
                "boilerplate.",
                width=width,
            )
        )
    else:
        result["comment"].append(
            wrap_para(
                'TLP Section 6.b "Copyright and License Notice" boilerplate'
                "text seems to have issues.",
                width=width,
            )
        )

    if re.search(NO_MOD_RFC, sotm):
        sotm = re.sub(NO_MOD_RFC, r"", sotm)
        result["comment"].append(
            wrap_para(
                "Document limits derivative works and/or RFC publication with "
                "a TLP Section 6.c.i boilerplate.",
                width=width,
            )
        )
    elif re.search(NO_MOD_NO_RFC, sotm):
        sotm = re.sub(NO_MOD_NO_RFC, r"", sotm)
        result["comment"].append(
            wrap_para(
                "Document limits derivative works and/or RFC publication with "
                "a TLP Section 6.c.ii boilerplate.",
                width=width,
            )
        )
    elif re.search(PRE_5378, sotm):
        sotm = re.sub(PRE_5378, r"", sotm)
        result["comment"].append(
            wrap_para(
                "Document limits derivative works and/or RFC publication with "
                'a TLP Section 6.c.iii "pre-5378" boilerplate.',
                width=width,
            )
        )

    if sotm:
        result["comment"].append(
            wrap_para(
                f'Found stray text in boilerplate: "{sotm}"',
                width=width,
            )
        )

    return result


def review_extend(review: dict, extension: dict) -> dict:
    """
    Extend the review with the lines in extensions by appending them to the
    various categories.

    @param      review     The review
    @param      extension  The extension

    @return     The extended review.
    """
    for cat in review:
        if cat in extension:
            review[cat].extend(extension[cat])

    for cat in extension:
        if cat not in review:
            review[cat] = extension[cat]

    return review


@click.command("review", help="Extract review from named items.")
@click.argument("items", nargs=-1)
@click.option(
    "--check-urls/--no-check-urls",
    "chk_urls",
    default=None,
    help="Check if URLs resolve.",
)
@click.option(
    "--check-refs/--no-check-refs",
    "chk_refs",
    default=None,
    help="Check references in the draft for issues.",
)
@click.option(
    "--check-grammar/--no-check-grammar",
    "chk_grammar",
    default=None,
    help="Check grammar in the draft for issues.",
)
@click.option(
    "--grammar-skip-rules",
    "grammar_skip_rules",
    type=str,
    help="Don't flag these grammar rules (use LanguageTool rule names, "
    "separate with commas).",
)
@click.option(
    "--check-meta/--no-check-meta",
    "chk_meta",
    default=None,
    help="Check metadata of the draft for issues.",
)
@click.option(
    "--check-inclusivity/--no-check-inclusivity",
    "chk_inclusiv",
    default=None,
    help="Check text for inclusive language issues.",
)
@click.option(
    "--check-boilerplate/--no-check-boilerplate",
    "chk_boilerpl",
    default=None,
    help="Check boilerplate text for issues.",
)
@click.option(
    "--check-misc/--no-check-misc",
    "chk_misc",
    default=None,
    help="Check text for miscellaneous issues.",
)
@click.option(
    "--check-tlp/--no-check-tlp",
    "chk_tlp",
    default=None,
    help="Check boilerplate for TLP issues.",
)
@click.pass_obj
def review_items(
    state: object,
    items: list,
    chk_urls: bool,
    chk_refs: bool,
    chk_grammar: bool,
    chk_meta: bool,
    chk_inclusiv: bool,
    chk_boilerpl: bool,
    chk_misc: bool,
    chk_tlp: bool,
    grammar_skip_rules: str,
) -> None:
    """
    Extract reviews from named items.

    @param      items        The items to extract reviews from
    @param      datatracker  The datatracker URL to use
    @param      chk_urls     Whether to check URLs for reachability

    @return     -
    """

    chk_urls = state.default if chk_urls is None else chk_urls
    chk_refs = state.default if chk_refs is None else chk_refs
    chk_grammar = state.default if chk_grammar is None else chk_grammar
    chk_meta = state.default if chk_meta is None else chk_meta
    chk_inclusiv = state.default if chk_inclusiv is None else chk_inclusiv
    chk_boilerpl = state.default if chk_boilerpl is None else chk_boilerpl
    chk_misc = state.default if chk_misc is None else chk_misc
    chk_tlp = state.default if chk_tlp is None else chk_tlp

    current_directory = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        log.debug("tmp dir %s", tmp)
        if not items:
            items = ["/dev/stdin"]

        for item in items:
            if os.path.isdir(item):
                for dir_item in os.listdir(item):
                    dir_item = os.path.join(item, dir_item)
                    if os.path.isfile(dir_item) and dir_item.endswith(".txt"):
                        items.append(dir_item)
                continue

            if not os.path.exists(item):
                log.warning("%s does not exist, skipping", item)
                continue

            orig = None
            if item != "/dev/stdin":
                os.chdir(tmp)
                orig_item = os.path.basename(item)
                get_items([orig_item], state.datatracker)
                orig = read(orig_item)
                os.chdir(current_directory)
            rev = read(item)
            if orig is None:
                log.error(
                    "No original for %s, cannot review, "
                    "only performing checks",
                    item,
                )
                orig = rev
            orig_lines = orig.splitlines(keepends=True)
            rev = rev.splitlines(keepends=True)
            review = review_item(orig_lines, rev)
            status = get_status(orig)
            name = basename(item)
            not_id = not name.startswith("draft-")

            if chk_misc:
                unescaped = html.unescape(orig)
                if orig != unescaped:
                    entities = []
                    diff = list(
                        difflib.ndiff(
                            orig_lines,
                            unescaped.splitlines(keepends=True),
                            linejunk=None,
                            charjunk=None,
                        )
                    )
                    for line in diff:
                        if re.search(r"^- ", line):
                            entities.extend(
                                re.findall(r"(&#?\w+;)", line, re.IGNORECASE)
                            )

                    if entities:
                        review["nit"].append(
                            wrap_para(
                                f"The text version of this document contains "
                                f"these HTML entities, which might indicate "
                                f"issues with its XML source: "
                                f"{word_join(list(set(entities)))}",
                                width=state.width,
                            )
                        )

            if chk_boilerpl and not not_id:
                review_extend(
                    review, check_boilerplate(orig, status, state.width)
                )

            if chk_tlp:
                review_extend(review, check_tlp(orig, status, state.width))

            meta = fetch_meta(state.datatracker, name)
            if chk_meta and meta:
                review_extend(
                    review,
                    check_meta(state.datatracker, orig, meta, state.width),
                )

            check_xml(orig)
            verbose = state.verbose > 0
            if chk_grammar:
                review_extend(
                    review,
                    check_grammar(
                        rev, grammar_skip_rules, state.width, verbose
                    ),
                )

            if chk_refs and not not_id:
                review_extend(
                    review,
                    check_refs(
                        state.datatracker,
                        extract_refs(orig),
                        get_relationships(orig),
                        state.width,
                        name,
                        status,
                        meta,
                        orig,
                    ),
                )

            if chk_urls:
                result = []
                urls = extract_urls(orig)

                for url in urls:
                    if re.search(r"://tools\.ietf\.org", url, re.IGNORECASE):
                        result.append(url)

                if result:
                    review["nit"].append(
                        "These URLs point to tools.ietf.org, which is "
                        "being deprecated:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")
                    urls -= set(result)

                result = []
                for url in urls:
                    if not re.search(r"^https?:", url, re.IGNORECASE):
                        result.append(url)

                if result:
                    review["nit"].append(
                        "Found non-HTTP URLs in the document:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

                reachability = {u: fetch_url(u, verbose, "HEAD") for u in urls}
                result = []
                for url in urls:
                    if reachability[url] is None:
                        result.append(url)

                if result:
                    review["nit"].append(
                        "These URLs in the document did not return content:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

                result = []
                for url in urls:
                    if url.startswith("https:"):
                        continue
                    if reachability[url] is not None:
                        test_url = re.sub(r"^\w+:", r"https:", url)
                        if fetch_url(test_url, verbose, "HEAD") is not None:
                            result.append(url)

                if result:
                    review["nit"].append(
                        "These URLs in the document can probably be converted "
                        "to HTTPS:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

            if chk_inclusiv:
                review_extend(
                    review,
                    check_inclusivity(
                        unfold("".join(rev)), state.width, verbose
                    ),
                )

            fmt_review(review, state.width)


@click.command(
    "fetch-agenda",
    help="Download all ballot items on the current IESG agenda.",
)
@click.option(
    "--make-directory/--no-make-directory",
    "mkdir",
    default=True,
    help="Create agenda subdirectory for all downloaded ballot items.",
)
@click.option(
    "--save-agenda/--no-save-agenda",
    "save_agenda",
    default=True,
    help="Store the telechat agenda in JSON format.",
)
@click.option(
    "--strip/--no-strip",
    "strip",
    default=True,
    help="Strip headers, footers and pagination from downloaded items.",
)
@click.option(
    "--fetch-writeups/--no-fetch-writeups",
    "fetch_writeups",
    default=True,
    help="Fetch various write-ups related to the item.",
)
@click.pass_obj
def fetch_agenda(state: object, mkdir, save_agenda, strip, fetch_writeups):
    agenda = get_current_agenda(state.datatracker)
    if "telechat-date" not in agenda:
        return
    items = get_items_on_agenda(agenda)

    if mkdir:
        current_directory = os.getcwd()
        agenda_directory = agenda["telechat-date"]
        if not os.path.isdir(agenda_directory):
            os.mkdir(agenda_directory)
        os.chdir(agenda_directory)

    current_items = set(os.listdir())
    for item in [
        "ballot_writeup_text",
        "last_call_text",
        "protocol_writeup",
        "ballot_rfceditornote_text",
        "agenda.json",
    ]:
        if item in current_items:
            current_items.remove(item)

    if save_agenda:
        write(json.dumps(agenda, indent=4), "agenda.json")

    log.info(
        "Downloading ballot items from %s IESG agenda",
        agenda["telechat-date"],
    )

    gotten = get_items(items, state.datatracker, strip, fetch_writeups)
    if gotten:
        extra = current_items - set(gotten)
        if extra:
            log.warning("Directory contains extra files: %s.", extra)

    if mkdir:
        os.chdir(current_directory)


cli.add_command(extract_urls_from_items)
cli.add_command(fetch)
cli.add_command(fetch_agenda)
cli.add_command(review_items)
cli.add_command(strip_items)

if __name__ == "__main__":
    cli()
