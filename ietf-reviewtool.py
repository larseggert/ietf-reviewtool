#! /usr/bin/env python3

"""
Review tool for IETF documents.
"""

import argparse
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


def get_items(items: list, datatracker: str, strip: bool = True) -> None:
    """
    Download named items into files of the same name in the current directory.
    Does not overwrite existing files. Names need to include the revision,
    and may or may not include the ".txt" suffix.

    @param      items  The items to download.

    @return     -
    """
    logging.debug(items)
    for item in items:
        file_name = item
        if not file_name.endswith(".txt"):
            file_name += ".txt"
        if os.path.isfile(file_name):
            logging.warning("%s exists, skipping", file_name)
            continue

        logging.info("Getting %s", item)
        cache = None
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
            url = "https://ietf.org/cr/" + file_name
            cache = os.getenv("IETF_CONFLICT_REVIEWS")
            strip = False
        else:
            die("Unknown item type: ", item)

        text = None
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


def section_and_paragraph(nxt: str, cur: str, sec_para: tuple) -> tuple:
    """
    Return a tuple consisting of the current paragraph number and section title,
    based on the next and current lines of text and the current paragraph number
    and section title tuple.

    @param      nxt       The next line in the diff.
    @param      cur       The current line in the diff
    @param      sec_para  The current (paragraph number, section name) tuple.

    @return     An updated (paragraph number, section name) tuple.
    """
    para = sec_para[0] if 0 in sec_para else 0
    sec = sec_para[1] if 1 in sec_para else None

    # track paragraphs
    if nxt is None or re.search(r"^[\- ] +$", nxt):
        # track sections
        sec = re.search(
            r"""^[- ][ ](Abstract|Status[ ]of[ ]This[ ]Memo|Copyright[ ]Notice|
            Table[ ]of[ ]Contents|Author(?:'?s?'?)?[ ]Address(?:es)?|
            [0-9]+(?:\.[0-9]+)*\.?)[ ]""",
            cur,
            re.VERBOSE,
        )
        if sec:
            sec = sec.group(1)
            para = 0
            sec = (
                "Section " + re.sub(r"(.*)\.$", r"\1", sec)
                if re.match(r"\d", sec)
                else f'"{sec}"'
            )
        else:
            para += 1
    return (para, sec)


def fmt_section_and_paragraph(sec_para: tuple, cat: str) -> str:
    """
    Return a formatted prefix line indicating the current section name,
    paragraph number, and category.

    @param      sec_para  The current (paragraph number, section name) tuple.
    @param      cat       The category to indicate.

    @return     A formatted prefix line.
    """
    line = f"{sec_para[1]}, p" if sec_para[1] else "P"
    line += f"aragraph {sec_para[0]}, {cat}:\n"
    return line


def fmt_nit(changed: list, indicator: list, sec_para: tuple) -> list:
    """
    Format a nit.

    @param      changed    Changed lines.
    @param      indicator  Indicator lines.
    @param      sec_para   The current (paragraph number, section name) tuple.

    @return     The formatted nit.
    """
    result = [fmt_section_and_paragraph(sec_para, "nit")]
    for prefix in ["-", "+"]:
        for tup in zip(changed[prefix], indicator[prefix]):
            # add the changed line followed by an indicator line
            result.append(tup[0])
            if tup[1]:
                result.append(tup[1].replace("?", prefix, 1))
        indicator[prefix] = []
        changed[prefix] = []
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
    sec_para = ()
    prev = None
    result = []

    for num, cur in enumerate(diff):
        kind = cur[0]
        nxt = diff[num + 1] if num < len(diff) - 1 else None
        nxt_kind = nxt[0] if nxt else None
        sec_para = section_and_paragraph(nxt, cur, sec_para)

        if kind in ["+", "-"] and nxt_kind == "?":
            changed[kind].append(cur)

        elif kind == "?" and prev in ["+", "-"]:
            indicator[prev].append(cur)

        elif kind in ["+", "-"] and prev == "?":
            changed[kind].append(cur)
            indicator[kind].append(None)

        elif changed["-"] or changed["+"]:
            result.extend(fmt_nit(changed, indicator, sec_para))

        prev = kind

    if changed["-"] or changed["+"]:
        result.extend(fmt_nit(changed, indicator, sec_para))

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

        if cur == "+ \n":
            continue

        kind = cur[0]
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


def fmt_comment(item: dict, sec_para: tuple) -> list:
    result = [fmt_section_and_paragraph(sec_para, item["cat"])]
    result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
    if item["ctx"]:
        result.append("\n")
    result.extend([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])
    if item["txt"]:
        result.append("\n")
    item.clear()
    return result


def gather_comments(diff: list) -> dict:
    """
    Return a dict that contains lists of all comments of all categories.

    @param      diff  A diff with nits removed (by strip_nits_from_diff).

    @return     A review dict.
    """
    result = {"discuss": [], "comment": [], "nit": []}
    sec_para = ()
    item = {}

    for num, cur in enumerate(diff):
        nxt = diff[num + 1] if num < len(diff) - 1 else None
        sec_para = section_and_paragraph(nxt, cur, sec_para)

        start = re.search(
            r"^\+ (?:(D(?:ISCUSS)|C(?:OMMENT)|N(?:IT)):?)? *(.*)", cur
        )
        if start and start.group(1):
            if "cat" in item:
                result[item["cat"]].extend(fmt_comment(item, sec_para))
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
                result[item["cat"]].extend(fmt_comment(item, sec_para))

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

    diff = list(difflib.ndiff(orig, rev, linejunk=None, charjunk=None))
    nits = gather_nits(diff)
    diff = strip_nits_from_diff(diff)
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


def review_items(items: list, datatracker: str) -> None:
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
            orig = read(orig_item).splitlines(keepends=True)
            os.chdir(current_directory)
            rev = read(item).splitlines(keepends=True)
            review = review_item(orig, rev)
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
            possible: IETF_RFCS, IETF_IDS, IETF_CHARTERS""",
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
        get_items(items, args.datatracker, args.strip)
        if args.mkdir:
            os.chdir(current_directory)

    elif args.tool == "fetch":
        get_items(args.items, args.datatracker, args.strip)

    elif args.tool == "strip":
        strip_items(args.items, args.in_place)

    elif args.tool == "review":
        review_items(args.items, args.datatracker)


if __name__ == "__main__":
    main()
