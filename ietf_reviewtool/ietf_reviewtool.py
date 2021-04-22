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
import json
import logging
import os
import re
import sys
import tempfile
import textwrap
import urllib.parse
import xml.etree.ElementTree

import appdirs
import click
import language_tool_python
import requests
import requests_cache

log = logging.getLogger(__name__)


SECTION_PATTERN = re.compile(
    r"""^(?:[\- ]\s)?(Abstract|Status\sof\sThis\sMemo|Copyright\sNotice|
        Table\sof\sContents|Author(?:'?s?'?)?\sAddress(?:es)?|
        (?:Appendix\s+)?[\dA-Z]+(?:\.\d+)*\.?|
        \d+(?:\.\d+)*\.?)(.*)""",
    re.VERBOSE,
)


class State:
    def __init__(self, datatracker=None, verbose=0):
        self.datatracker = datatracker
        self.verbose = verbose


@click.group(help="Review tool for IETF documents.")
@click.option(
    "--verbose",
    "-v",
    default=0,
    count=True,
    help="Be more verbose during operation.",
)
@click.option(
    "--datatracker",
    default="https://datatracker.ietf.org/",
    help="IETF Datatracker base URL.",
)
@click.pass_context
def cli(ctx: object, datatracker: str, verbose: int) -> None:
    datatracker = re.sub(r"/+$", "", datatracker)
    ctx.obj = State(datatracker, verbose)
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


def fetch_url(url: str, use_cache: bool = True, method: str = "GET") -> str:
    """
    Fetches the resource at the given URL or checks its reachability (when
    method is "HEAD".) In the latter case, the cache is also disabled.

    @param      url        The URL to fetch
    @param      use_cache  Whether to use the local cache or not
    @param      method     The method to use (default "GET")

    @return     The decoded content of the resource (or the empty string for a
                successful HEAD request). None if an error occurred.
    """
    try:
        log.debug(
            "%s %scache %s", method.lower(), "no" if not use_cache else "", url
        )
        if use_cache is False:
            with requests_cache.disabled():
                response = requests.request(method, url, allow_redirects=True)
        else:
            response = requests.request(method, url, allow_redirects=True)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        log.error("%s -> %s", url, err)
        return None
    return response.text


def read(file_name: str) -> str:
    """
    Read a file into a string.

    @param      file_name  The item to read

    @return     The content of the item.
    """
    try:
        file = open(file_name, "r")
    except FileNotFoundError as err:
        log.error("%s -> %s", file_name, err)
        return None
    text = file.read()
    file.close()
    return text


def write(text: str, file_name: str) -> None:
    """
    Write a string into a file.

    @param      text       The text to write
    @param      file_name  The file name to write to

    @return     -
    """
    file = open(file_name, "w")
    text = file.write(text)
    file.close()
    return text


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
    folded = re.sub(r"([\-/])\n", r"\1", folded)
    folded = re.sub(r"\n", r" ", folded)
    folded = re.sub(rand, r"\n\n", folded)

    return folded


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
    urls = re.findall(
        r"(?:https?|ftp)://(?:-\.)?(?:[^\s/?\.#]+\.?)+(?:/[^\s)\">;]*)?",
        text,
        re.IGNORECASE,
    )
    urls = [u.rstrip(".\"'>;") for u in urls]

    if not examples:
        # remove example URLs
        urls = [
            u
            for u in urls
            if not re.search(
                r"example\.(?:com|net|org)|\.example$",
                urllib.parse.urlparse(u).netloc,
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
                flags=re.VERBOSE,
            )
        ]

    return urls


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
                        (Jan|Feb|Mar(ch)?|Apr(il)?|
                        May|June?|July?|Aug|Sep|Oct|Nov|Dec)\s
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
        type_events.sort(
            key=lambda k: datetime.datetime.fromisoformat(k["time"]),
            reverse=True,
        )
        text = type_events[0]["text"]

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
) -> None:
    """
    Download named items into files of the same name in the current directory.
    Does not overwrite existing files. Names need to include the revision, and
    may or may not include the ".txt" suffix.

    @param      items        The items to download
    @param      datatracker  The datatracker URL to use
    @param      strip        Whether to run strip() on the downloaded item
    @param      get_writeup  Whether to download associated write-ups

    @return     -
    """
    log.debug(items)
    for item in items:
        file_name = item
        if not file_name.endswith(".txt"):
            file_name += ".txt"

        if get_writeup:
            get_writeups(datatracker, item)

        if os.path.isfile(file_name):
            log.warning("%s exists, skipping", file_name)
            continue

        log.info("Getting %s", item)
        cache = None
        text = None
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
            strip = False
        elif item.startswith("conflict-review-"):
            doc = re.sub(r"conflict-review-(.*)", r"draft-\1", item)
            text = get_writeups(datatracker, doc)
            # TODO: in-progress conflict-reviews are not in the cache
            # cache = os.getenv("IETF_CONFLICT_REVIEWS")
            strip = False
        else:
            die("Unknown item type: ", item)

        if cache is not None:
            cache_file = os.path.join(cache, file_name)
            if os.path.isfile(cache_file):
                log.debug("Using cached %s", item)
                text = read(cache_file)
            else:
                log.debug("No cached copy of %s in %s", item, cache)

        if text is None:
            text = fetch_url(url)

        if text is not None:
            if strip:
                log.debug("Stripping %s", item)
                text = strip_pagination(text)
            write(text, file_name)


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
    log.debug(items)
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
    pat = {True: r"^[\- ] +$", False: r"^ *$"}
    if re.search(pat[is_diff], cur):
        para += 1

    # track sections
    pot_sec = SECTION_PATTERN.search(cur)
    pat = {True: r"^([\- ] +$|\+ )", False: r"^( *$)"}
    if pot_sec and re.search(pat[is_diff], nxt):
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

        elif kind in ["-"] and nxt_kind == "+":
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
    Calculates a diff between orig and rev..

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


def fmt_review(review: dict, ruler: int = 79) -> None:
    """
    Format a review dict for datatracker submission.

    @param      review  The review to format
    @param      ruler   The column number to wrap the review to

    @return     Wrapped text version of the review.
    """
    boilerplate = {
        "discuss": None,
        "comment": None,
        "nit": (
            "All comments below are very minor suggestions "
            "that you may choose to incorporate in some way (or ignore), "
            "as you see fit. There is no need to let me know what you did "
            "with these suggestions."
        ),
    }

    for category in boilerplate:
        if review[category]:
            print("-" * ruler)
            print(category.upper())
            print("-" * ruler)
            if boilerplate[category]:
                print(textwrap.fill(boilerplate[category], width=ruler), "\n")

            for line in review[category]:
                print(line, end="")


def extract_refs(text: list) -> dict:
    """
    Return a dict of references found in the text as well as the normative and
    informative reference sections.

    @param      text  The text to parse for references

    @return     A dict with lists of found references.
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
            parts[part],
            re.IGNORECASE,
        )

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


def level_ok(kind: str, level: str) -> bool:
    """
    Check if a document reference is allowed (i.e., is not a DOWNREF) for a
    document at a given standards level.

    @param      kind   The kind of reference (normative or informative.)
    @param      level  The status level of the reference

    @return     False if this is a DOWNREF, True otherwise.
    """
    if kind.lower() == "normative":
        return level is not None and level.lower() in [
            "best current practice",
            "proposed standard",
            "draft standard",
            "internet standard",
        ]
    if kind.lower() == "informative":
        return True
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
    return re.sub(r"^\[(.*)\]$", r"\1", tag)


def check_refs(datatracker: str, refs: dict, name: str, status: str) -> list:
    """
    Check the references.

    @param      datatracker  The datatracker URL to use
    @param      refs         The references to check
    @param      name         The name of this document.
    @param      status       The standards level of the given document

    @return     List of messages.
    """
    result = []
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
            result.append(f"Duplicate {kind} references: {', '.join(dupes)}")

        dupes = duplicates(tgts)
        if dupes:
            tags = [t[0] for t in refs[kind] if t[1] in dupes]
            result.append(
                f"Duplicate {kind} references to: {', '.join(dupes)}"
            )

    norm = set(e[0] for e in refs["normative"])
    info = set(e[0] for e in refs["informative"])
    both = norm | info
    text = {"[" + r + "]" for r in {untag(r) for r in refs["text"]}}

    if norm & info:
        result.append(
            "Reference entries duplicated in both normative and "
            f"informative sections: {', '.join(norm & info)}"
        )

    if both < text:
        result.append(
            f"No reference entries found for: {', '.join(text - both)}"
        )
    elif both > text:
        result.append(f"Uncited references: {', '.join(both - text)}")

    for kind in ["normative", "informative"]:
        for tag, doc in refs[kind]:
            ntag = untag(tag)
            if doc:
                docname = re.search(
                    r"^(rfc\d+|(draft-[-a-z\d_.]+)-\d{2,})", doc
                )
            if not doc or not docname:
                log.info(
                    "No metadata available for %s reference %s", kind, tag
                )
                continue

            groups = list(docname.groups())
            docname = groups[1] if groups[1] else groups[0]
            docname = re.sub(r"rfc0*(\d+)", r"rfc\1", docname)

            if status.lower() not in ["informational", "experimental"]:
                url = datatracker + "/doc/" + docname + "/doc.json"
                meta = fetch_url(url)

                if not meta:
                    log.info(
                        "No metadata available for %s reference %s", kind, tag
                    )
                    continue

                meta = json.loads(meta)
                level = meta["std_level"] or meta["intended_std_level"]

                if not level_ok(kind, level) and docname not in downrefs:
                    if level is None:
                        result.append(
                            f"Possible DOWNREF from this {status} doc "
                            f"to {ntag}"
                        )
                    else:
                        result.append(
                            f"DOWNREF from this {status} doc to {level} {ntag}"
                        )

            obsoleted_by = fetch_dt(
                datatracker,
                "relateddocument/?relationship__slug=obs&target__name="
                + docname,
            )
            if obsoleted_by:
                if len(obsoleted_by) > 1:
                    log.warning("%s obsoleted by more than one doc", docname)
                else:
                    obs_by = fetch_dt(datatracker, obsoleted_by[0]["source"])
                    if "rfc" in obs_by:
                        result.append(
                            f"Obsolete reference to {ntag}, "
                            f"obsoleted by RFC{obs_by['rfc']}"
                        )

    return result


def get_status(doc: str) -> str:
    """
    Extract the standards level status of a given document..

    @param      doc   The document to extract the level from

    @return     The status of the document..
    """
    status = re.search(
        r"^(?:[Ii]ntended )?[Ss]tatus:\s*((?:\w+\s)+)",
        doc,
        re.MULTILINE,
    )
    return status.group(1).strip() if status else None


def check_xml(doc: str) -> None:
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


def check_grammar(review: str) -> list:
    issues = [
        i
        for i in language_tool_python.LanguageTool("en").check("".join(review))
        if i.ruleId
        not in [
            "ARROWS",
            "COMMA_PARENTHESIS_WHITESPACE",
            "COPYRIGHT",
            "CURRENCY",
            "DASH_RULE",
            "EN_QUOTES",
            "ENGLISH_WORD_REPEAT_BEGINNING_RULE",
            "KEY_WORDS",
            "MULTIPLICATION_SIGN",
            "PLUS_MINUS",
            "PUNCTUATION_PARAGRAPH_END",
            "RETURN_IN_THE",
            "UPPERCASE_SENTENCE_START",
            "WHITESPACE_RULE",
            "WORD_CONTAINS_UNDERSCORE",
        ]
    ]

    para_sec = None
    cur = 0
    pos = 0
    result = []
    for issue in issues:
        while pos + len(review[cur + 1]) < issue.offset:
            para_sec = section_and_paragraph(
                review[cur + 1], review[cur], para_sec, is_diff=False
            )
            pos += len(review[cur])
            cur += 1

        result.append(fmt_section_and_paragraph(para_sec, "nit"))
        context = issue.context.lstrip(".")
        offset = issue.offsetInContext - (len(issue.context) - len(context))
        context = context.rstrip(".")

        compressed = re.sub(r"\s+", r" ", context[0:offset])
        offset -= len(context[0:offset]) - len(compressed)
        context = re.sub(r"\s+", r" ", context)

        result.append("> " + context + "\n")
        result.append("> " + " " * offset + "^" * issue.errorLength + "\n")

        message = (
            issue.message.replace("“", '"')
            .replace("”", '"')
            .replace("‘", "'")
            .replace("’", "'")
        )

        result.append(textwrap.fill(f"{message}", width=79) + "\n\n")

    return result


def check_meta(meta: dict) -> list:
    result = []
    # print(json.dumps(meta, indent=4))

    num_authors = len(meta["authors"])
    if num_authors > 5:
        result += textwrap.fill(
            f"The document has {num_authors} authors, which exceeds the "
            "recommended author limit. I assume the sponsoring AD has agreed "
            "that this is appropriate?\n",
            width=79,
        )

    if re.match("Not OK", meta["iana_review_state"], re.IGNORECASE):
        result += (
            "There seem to be unresolved IANA issues with this document.\n"
        )

    if not meta["consensus"]:
        result += "There does not seem to be consensus for this document.\n"

    if meta["stream"] != "IETF":
        result += "This does not seem to be an IETF-stream document.\n"

    return result


@click.command("review", help="Extract review from named items.")
@click.argument("items", nargs=-1)
@click.option(
    "--check-urls/--no-check-urls",
    "chk_urls",
    default=True,
    help="Check if URLs resolve.",
)
@click.option(
    "--check-refs/--no-check-refs",
    "chk_refs",
    default=True,
    help="Check references in the draft for issues.",
)
@click.option(
    "--check-grammar/--no-check-grammar",
    "chk_grammar",
    default=True,
    help="Check grammar in the draft for issues.",
)
@click.option(
    "--check-meta/--no-check-meta",
    "chk_meta",
    default=True,
    help="Check metadata of the draft for issues.",
)
@click.pass_obj
def review_items(
    state: object,
    items: list,
    chk_urls: bool,
    chk_refs: bool,
    chk_grammar: bool,
    chk_meta: bool,
) -> None:
    """
    Extract reviews from named items.

    @param      items        The items to extract reviews from
    @param      datatracker  The datatracker URL to use
    @param      chk_urls     Whether to check URLs for reachability

    @return     -
    """
    log.debug(items)
    current_directory = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        log.debug("tmp dir %s", tmp)
        for item in items:
            if os.path.isdir(item):
                for dir_item in os.listdir(item):
                    dir_item = os.path.join(item, dir_item)
                    if os.path.isfile(dir_item) and dir_item.endswith(".txt"):
                        items.append(dir_item)
                log.debug(items)
                continue

            if not os.path.isfile(item):
                log.warning("%s does not exist, skipping", item)
                continue

            os.chdir(tmp)
            orig_item = os.path.basename(item)
            get_items([orig_item], state.datatracker)
            orig = read(orig_item)
            if orig is None:
                log.error("No original for %s, cannot review", orig_item)
                continue

            os.chdir(current_directory)
            rev = read(item).splitlines(keepends=True)
            review = review_item(orig.splitlines(keepends=True), rev)

            url = state.datatracker + "/doc/" + basename(item) + "/doc.json"
            meta = fetch_url(url)

            if chk_meta:
                if not meta:
                    log.warning("No metadata available for %s", basename(item))
                else:
                    review["comment"].extend(check_meta(json.loads(meta)))

            check_xml(orig)

            if chk_grammar:
                review["nit"].extend(check_grammar(rev))

            if chk_refs:
                refs = extract_refs(orig)
                result = check_refs(
                    state.datatracker, refs, basename(item), get_status(orig)
                )
                if result:
                    review["nit"].append(
                        "These reference issues exist in the document:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

            if chk_urls:
                result = []
                urls = extract_urls(orig)
                reachability = {
                    u: fetch_url(u, state.verbose > 0, "HEAD") for u in urls
                }
                for url in urls:
                    if reachability[url] is None:
                        result.append(url)

                if result:
                    review["nit"].append(
                        "These URLs in the document did not return content:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

            fmt_review(review)


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

    if save_agenda:
        write(json.dumps(agenda, indent=4), "agenda.json")

    log.info(
        "Downloading ballot items from %s IESG agenda",
        agenda["telechat-date"],
    )
    get_items(items, state.datatracker, strip, fetch_writeups)
    if mkdir:
        os.chdir(current_directory)


cli.add_command(fetch_agenda)
cli.add_command(fetch)
cli.add_command(strip_items)
cli.add_command(review_items)

if __name__ == "__main__":
    cli()
