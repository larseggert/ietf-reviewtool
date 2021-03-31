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

import argparse
import datetime
import difflib
import json
import logging
import os
import re
import sys
import tempfile
import textwrap
import urllib.error
import urllib.request
import urllib.parse


def die(msg: list, err: int = 1) -> None:
    """
    Print a message and exit with an error code.

    @param      msg   The message to print.

    @return
    """
    logging.error(msg)
    sys.exit(err)


def fetch_url(url: str) -> str:
    """
    Fetches the resource at the given URL.

    @param      url   The URL to fetch

    @return     The decoded content of the resource.
    """
    try:
        logging.debug("fetch %s", url)
        resource = urllib.request.urlopen(url)
        charset = resource.headers.get_content_charset()
        if charset is None:
            charset = "utf8"
        text = resource.read().decode(charset)
    except (urllib.error.URLError, urllib.error.HTTPError) as err:
        logging.error("%s -> %s", url, err)
        return None
    return text


def read(file_name: str) -> str:
    """
    Read a file into a string.

    @param      file_name  The item to read.

    @return     The content of the item.
    """
    file = open(file_name, "r")
    text = file.read()
    file.close()
    return text


def write(text: str, file_name: str) -> None:
    """
    Write a string into a file.

    @param      text       The text to write.
    @param      file_name  The file name to write to.

    @return     -
    """
    file = open(file_name, "w")
    text = file.write(text)
    file.close()
    return text


def extract_urls(
    text: str, examples: bool = False, common: bool = False
) -> set:
    """
    Return a list of URLs in a text string.

    @param      text      The text to extract URLs from.
    @param      examples  Include example URLs.
    @param      common    Include URLs that are common in IETF documents.

    @return     List of URLs.
    """

    # prepare text
    rand = r"bYYO2hxg2Bg4HhwEsbJQSSucukxfAbAIcDrPu5dw"
    text = re.sub(r"\n{2,}", rand, text, flags=re.MULTILINE)
    text = re.sub(r"^\s*", r"", text, flags=re.MULTILINE)
    text = re.sub(r"[\n\r]+", r"", text, flags=re.MULTILINE)
    text = re.sub(rand, r"\n", text, flags=re.MULTILINE)

    # find all URLs
    urls = re.findall(
        r"(?:https?|ftp)://(?:-\.)?(?:[^\s/?\.#]+\.?)+(?:/[^\s)\">]*)?",
        text,
        flags=re.UNICODE | re.IGNORECASE,
    )

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
                    (www\.)?rfc-editor\.org/info/rfc[0-9]+|
                    (www\.)?ietf\.org/archive/id/draft-""",
                u,
                flags=re.VERBOSE,
            )
        ]

    return urls


def get_current_agenda(datatracker: str) -> dict:
    """
    Download and the current IESG telechat agenda in JSON format.

    @return     The current agenda as a dict.
    """
    agenda = fetch_url(datatracker + "/iesg/agenda/agenda.json")
    if agenda is None:
        return {}
    return json.loads(agenda)


def get_items_on_agenda(agenda: dict) -> list:
    """
    Given an IESG telechat agenda dict, return the list of items that
    are on it.

    @param      agenda  An agenda dict.

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

    @param      text  The text of an RFC or Internet-Draft.

    @return     The stripped version of the text.
    """
    stripped = ""
    new_page = False
    sentence = False
    have_blank = False
    for line in text.split("\n"):
        # FIXME: doesn't always live a blank line after a figure caption
        mod = re.sub(r"\r", "", line)
        mod = re.sub(r"[ \t]+$", "", mod)
        if re.search(r"\[?[Pp]age [0-9ivx]+\]?[ \t\f]*$", mod):
            continue
        if (
            re.search(r"^[ \t]*\f", mod)
            or re.search(
                r"^ *I(nternet|NTERNET).D(raft|RAFT).+[12][0-9]{3} *$",
                mod,
            )
            or re.search(r"^ *Draft.+[12][0-9]{3} *$", mod)
            or re.search(r"^(RFC.+[0-9]+|draft-[-a-z0-9_.]+.*[0-9]{4})$", mod)
            or re.search(
                r"""(Jan|Feb|Mar(ch)?|Apr(il)?|
                        May|June?|July?|Aug|Sep|Oct|Nov|Dec)[ ]
                        (19[89][0-9]|20[0-9]{2})[ ]*$""",
                mod,
                re.VERBOSE,
            )
        ):
            new_page = True
            continue
        if new_page and re.search(r"^ *draft-[-a-z0-9_.]+ *$", line):
            continue
        if re.search(r"^[^ \t]", mod):
            sentence = True
        if re.search(r"[^ \t]", mod):
            if (new_page and sentence) or (not new_page and have_blank):
                stripped += "\n"
            have_blank = False
            sentence = False
            new_page = False
        if re.search(r"[.:][ \t]*$", mod):
            sentence = True
        if re.search(r"^[ \t]*$", mod):
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
    return re.sub(r"^(?:.*/)?(.*[^-0-9]+)(-[0-9]+)+(?:\.txt)?$", r"\1", item)


def get_writeups(datatracker: str, item: str) -> str:
    """
    Download related document writeups for an item from the datatracker.

    @param      datatracker  The datatracker URL to use
    @param      item         The item to download writeups for

    @return     The text of the writeup, if only a single one existed, else
                None.
    """
    url = (
        datatracker
        + "/api/v1/doc/writeupdocevent/?format=json&doc__name="
        + basename(item)
    )
    doc_events = fetch_url(url)
    if doc_events is not None:
        doc_events = json.loads(doc_events)["objects"]
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
        logging.debug(events)
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
                logging.debug("no %s for %s", evt, item)

        return text if len(events) == 1 else None


def get_items(
    items: list, datatracker: str, strip: bool = True, get_writeup=False
) -> None:
    """
    Download named items into files of the same name in the current directory.
    Does not overwrite existing files. Names need to include the revision, and
    may or may not include the ".txt" suffix.

    @param      items        The items to download.
    @param      datatracker  The datatracker URL to use
    @param      strip        Whether to run strip() on the downloaded item
    @param      get_writeup  Whether to download associated write-ups

    @return     -
    """
    logging.debug(items)
    for item in items:
        file_name = item
        if not file_name.endswith(".txt"):
            file_name += ".txt"

        if get_writeup:
            get_writeups(datatracker, item)

        if os.path.isfile(file_name):
            logging.warning("%s exists, skipping", file_name)
            continue

        logging.info("Getting %s", item)
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
                r"(.*)(((-[0-9]+){2}).txt)$", r"\1/withmilestones\2", file_name
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
                logging.debug("Using cached %s", item)
                text = read(cache_file)
            else:
                logging.debug("No cached copy of %s in %s", item, cache)

        if text is None:
            text = fetch_url(url)

        if strip:
            logging.debug("Stripping %s", item)
            text = strip_pagination(text)
        if text is not None:
            write(text, file_name)


def strip_items(items: list, in_place: bool = False) -> None:
    """
    Run strip_pagination over the named items.

    @param      items  The items to strip.

    @return     -
    """
    logging.debug(items)
    for item in items:
        if not os.path.isfile(item):
            logging.warning("%s does not exist, skipping", item)
            continue

        text = strip_pagination(read(item))

        if text is not None:
            if not in_place:
                item += ".stripped"
                if os.path.isfile(item):
                    logging.warning("%s exists, skipping", item)
                    continue

            logging.debug("Saving stripped version as %s", item)
            write(text, item)


def section_and_paragraph(nxt: str, cur: str, para_sec: list) -> list:
    """
    Return a list consisting of the current paragraph number and section title,
    based on the next and current lines of text and the current paragraph number
    and section title list.

    @param      nxt       The next line in the diff.
    @param      cur       The current line in the diff
    @param      para_sec  The current (paragraph number, section name) list.

    @return     An updated (paragraph number, section name) list.
    """
    [para, sec, had_nn] = (
        para_sec if para_sec is not None else [1, None, False]
    )

    # track paragraphs
    if re.search(r"^[\- ] +$", cur):
        para += 1

    # track sections
    pot_sec = re.search(
        r"""^[- ][ ](Abstract|Status[ ]of[ ]This[ ]Memo|Copyright[ ]Notice|
        Table[ ]of[ ]Contents|Author(?:'?s?'?)?[ ]Address(?:es)?|
        Appendix[ ]+[0-9A-Z]+(?:\.[0-9]+)*\.?|
        [0-9]+(?:\.[0-9]+)*\.?)""",
        cur,
        re.VERBOSE,
    )
    if pot_sec and re.search(r"^([\- ] +$|\+ )", nxt):
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

    @param      para_sec  The current (paragraph number, section name) list.
    @param      cat       The category to indicate.

    @return     A formatted prefix line.
    """
    line = f"{para_sec[1]}, p" if para_sec[1] else "P"
    line += f"aragraph {para_sec[0]}, {cat}:\n"
    return line


def fmt_nit(changed: list, indicator: list, para_sec: list) -> list:
    """
    Format a nit.

    @param      changed    Changed lines.
    @param      indicator  Indicator lines.
    @param      para_sec   The current (paragraph number, section name) list.

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

    @param      diff  The diff to extract nits from.

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

    @param      diff  The diff to strip nits from.

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

    @param      item      The comment item dict.
    @param      para_sec  The current (paragraph number, section name) list.

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

    @param      diff  A diff with nits removed (by strip_nits_from_diff).

    @return     A review dict.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    para_sec = None
    item = {}

    for num, cur in enumerate(diff):
        nxt = diff[num + 1] if num < len(diff) - 1 else None

        start = re.search(r"^\+ (?:(DISCUSS|COMMENT|NIT):?)? *(.*)", cur)
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

    @param      orig  The original text.
    @param      rev   The revised text.

    @return     A diff between orig and rev.
    """

    # difflib can't deal with single lines it seems
    if len(orig) == 1:
        orig.append("\n")
    if len(rev) == 1:
        rev.append("\n")

    diff = list(difflib.ndiff(orig, rev, linejunk=None, charjunk=None))
    # print("diff ", diff)

    nits = gather_nits(diff)
    # print("nits ", nits)
    diff = strip_nits_from_diff(diff)
    # print("stripped ", diff)
    review = gather_comments(diff)
    review["nit"].extend(nits)
    return review


def fmt_review(review: dict, ruler: int = 79) -> None:
    """Format a review dict for datatracker submission."""
    boilerplate = {
        "discuss": None,
        "comment": None,
        "nit": (
            "All comments below are very minor change suggestions "
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


def review_items(items: list, datatracker: str, check_urls: bool) -> None:
    """
    Extract reviews from named items.

    @param      items  The items to extract reviews from.

    @return     -
    """
    logging.debug(items)
    current_directory = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        logging.debug("tmp dir %s", tmp)
        for item in items:
            if os.path.isdir(item):
                for dir_item in os.listdir(item):
                    dir_item = os.path.join(item, dir_item)
                    if os.path.isfile(dir_item) and dir_item.endswith(".txt"):
                        items.append(dir_item)
                logging.debug(items)
                continue

            if not os.path.isfile(item):
                logging.warning("%s does not exist, skipping", item)
                continue

            os.chdir(tmp)
            orig_item = os.path.basename(item)
            get_items([orig_item], datatracker)
            orig = read(orig_item)
            os.chdir(current_directory)
            rev = read(item).splitlines(keepends=True)
            review = review_item(orig.splitlines(keepends=True), rev)

            if check_urls:
                result = []
                urls = extract_urls(orig)
                texts = {u: fetch_url(u) for u in urls}
                for url in urls:
                    if texts[url] is None:
                        result.append(f" * {url}\n")

                if result:
                    result.insert(
                        0,
                        (
                            "The following URLs in the document "
                            "failed to return content:\n"
                        ),
                    )
                    review["nit"].extend(result)

            fmt_review(review)


def parse_args() -> dict:
    """
    Parse arguments.

    @return     Dict of parsed arguments.
    """
    main_parser = argparse.ArgumentParser(
        description="Review tool for IETF documents.",
        epilog="""In order to operate offline and to speed up operation,
            if you rsync the the various IETF documents onto your local disk,
            set these environment variables to use your local caches as much as
            possible: IETF_CHARTERS, IETF_CONFLICT_REVIEWS, IETF_IDS,
            IETF_RFCS, IETF_STATUS_CHANGES""",
    )

    main_parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help=("be more verbose during operation"),
    )

    main_parser.add_argument(
        "--datatracker",
        dest="datatracker",
        type=str,
        metavar="URL",
        default="https://dt.ietf.org/",
        help=("IETF Datatracker base URL"),
    )

    subparsers = main_parser.add_subparsers(
        help="desired review tool", dest="tool"
    )
    subparsers.required = True

    parser_fetch = subparsers.add_parser(
        "fetch",
        prog="fetch",
        help="download items (I-Ds, charters, RFCs, etc.)",
    )

    parser_fetch_agenda = subparsers.add_parser(
        "fetch-agenda",
        help=("download all ballot items on the current IESG agenda"),
    )

    parser_fetch_agenda.add_argument(
        "--make-directory",
        dest="mkdir",
        action=argparse.BooleanOptionalAction,
        default=True,
        required=False,
        help="create agenda subdirectory for all downloaded ballot items",
    )

    parser_fetch_agenda.add_argument(
        "--save-agenda",
        dest="save_agenda",
        action=argparse.BooleanOptionalAction,
        default=True,
        required=False,
        help="store the telechat agenda in JSON format",
    )

    for parser in [parser_fetch, parser_fetch_agenda]:
        parser.add_argument(
            "--strip",
            dest="strip",
            action=argparse.BooleanOptionalAction,
            default=True,
            required=False,
            help="strip headers, footers and pagination from downloaded I-Ds",
        )
        parser.add_argument(
            "--fetch-writeups",
            dest="writeups",
            action=argparse.BooleanOptionalAction,
            default=(parser == parser_fetch_agenda),
            required=False,
            help="fetch various write-ups related to the item",
        )

    parser_strip = subparsers.add_parser(
        "strip",
        prog="strip",
        help=("strip headers, footers and pagination from items"),
    )

    parser_strip.add_argument(
        "--in-place",
        dest="in_place",
        action=argparse.BooleanOptionalAction,
        default=False,
        required=False,
        help="overwrite original item with stripped version",
    )

    parser_review = subparsers.add_parser(
        "review",
        prog="review",
        help="extract review from named items",
    )

    parser_review.add_argument(
        "--check-urls",
        dest="check_urls",
        action=argparse.BooleanOptionalAction,
        default=True,
        required=False,
        help="check if URLs resolve",
    )

    for parser in [parser_fetch, parser_strip, parser_review]:
        parser.add_argument(
            "items",
            metavar="item",
            nargs="+",
            help="names of items to " + parser.prog,
        )

    return main_parser.parse_args()


def main() -> None:
    """
    Parse options and execute things.

    @return     -
    """
    args = parse_args()

    args.datatracker = re.sub(r"/+$", "", args.datatracker)

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.tool == "fetch-agenda":
        agenda = get_current_agenda(args.datatracker)
        if "telechat-date" not in agenda:
            return
        items = get_items_on_agenda(agenda)

        if args.mkdir:
            current_directory = os.getcwd()
            agenda_directory = agenda["telechat-date"]
            if not os.path.isdir(agenda_directory):
                os.mkdir(agenda_directory)
            os.chdir(agenda_directory)

        if args.save_agenda:
            write(json.dumps(agenda, indent=4), "agenda.json")

        logging.info(
            "Downloading ballot items from %s IESG agenda",
            agenda["telechat-date"],
        )
        get_items(items, args.datatracker, args.strip, args.writeups)
        if args.mkdir:
            os.chdir(current_directory)

    elif args.tool == "fetch":
        get_items(args.items, args.datatracker, args.strip, args.writeups)

    elif args.tool == "strip":
        strip_items(args.items, args.in_place)

    elif args.tool == "review":
        review_items(args.items, args.datatracker, args.check_urls)


if __name__ == "__main__":
    main()
