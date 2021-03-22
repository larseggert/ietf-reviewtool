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
import tempfile
import urllib.error
import urllib.request
import sys


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
            url = "https://www.ietf.org/archive/id/" + file_name
            cache = os.getenv("IETF_IDS")
        elif item.startswith("rfc"):
            url = "https://rfc-editor.org/rfc/" + file_name
            cache = os.getenv("IETF_RFCS")
        elif item.startswith("charter-"):
            url_pattern = re.sub(
                r"(.*)(((-[0-9]+){2}).txt)$", r"\1/withmilestones\2", file_name
            )
            url = datatracker + "/doc/" + url_pattern
            # TODO: the charters in rsync are wrapped differently, can't use
            # cache = os.getenv("IETF_CHARTERS")
            strip = False  # don't strip charters for review
        elif item.startswith("conflict-review-"):
            url = datatracker + "/doc/" + file_name
            # cache = os.getenv("IETF_RFCS")
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


def review_item(orig: str, rev: str) -> dict:
    """
    Calculates a diff between orig and rev..

    @param      orig  The original text.
    @param      rev   The revised text.

    @return     A diff between orig and rev.
    """
    review = {"discuss": [], "comment": [], "nit": []}
    changed = {"+": [], "-": []}
    indicator = {"+": [], "-": []}
    context = {}
    prev = None
    section = None
    para = 0

    for line in difflib.ndiff(orig, rev, linejunk=None, charjunk=None):
        print(line)
        context_start = re.search(
            r"^\+ (?:(D(?:ISCUSS)|C(?:OMMENT)|N(?:IT)):?)? *(.*)", line
        )
        if context_start and context_start.group(1):
            context["category"] = context_start.group(1).lower()
            context["section"] = section
            context["para"] = para
            context["inline"] = context_start.group(2) != ""
            context["text"] = []
            context["complete"] = False
            if context["inline"]:
                line = re.sub(r"" + context["category"] + ": *", "", line)
            else:
                continue

        if "category" in context and not context["complete"]:
            if re.search(r"^[\- ] ", line):
                context["text"].append(line)
                continue
            context["complete"] = True

        # track sections
        potential_section = re.search(
            r"""^[- ][ ](Abstract|Status[ ]of[ ]This[ ]Memo|Copyright[ ]Notice|
            Table[ ]of[ ]Contents|Author(?:'?s?'?)?[ ]Address(?:es)?|
            [0-9]+(?:\.[0-9]+)*\.?)""",
            line,
            re.VERBOSE,
        )
        if potential_section:
            section = potential_section.group(1)
            if re.search(r"\d", section):
                section = "Section " + re.sub(r"(.*)\.$", r"\1", section)
            else:
                section = "\"" + section + "\""
            para = 0

        # track paragraphs
        if re.search(r"^[\- ] +$", line):
            para += 1

        kind = re.search(r"^([+? -]) ", line).group(1)

        if kind == " ":
            complete = False
            category = "nit"
            if changed["+"] or changed["-"]:
                if "complete" in context and context["complete"]:
                    category = context["category"]
                    review[category].append(
                        f"{context['section']}, "
                        f"paragraph {context['para']}, "
                        f"{category}:\n"
                    )

                    for context_line in context["text"]:
                        if not re.match(r"^.. *$", context_line):
                            quoted = re.sub(r"^..(.*)", r"> \1", context_line)
                            review[category].append(quoted)
                    if context["text"]:
                        review[category].append("\n")
                else:
                    review[category].append(
                        f"{section}, paragraph {para}, nit:\n"
                    )

            for prefix in ["-", "+"]:
                # if there are no changes, continue
                if not changed[prefix]:
                    continue

                for i in range(len(changed[prefix])):
                    # skip changes that add or remove empty lines
                    if changed[prefix][i] in ("+ \n", "- \n"):
                        continue

                    # add the changed line followed by an indicator line
                    # (if present)
                    if context:
                        stripped = re.sub(
                            r"^\+ (.*)",
                            r"\1",
                            changed[prefix][i],
                        )
                        review[category].append(stripped)
                    else:
                        stripped = re.sub(
                            r"^(\+ )(?:(D(?:ISCUSS)|C(?:OMMENT)|N(?:IT)):?)?( *.*)",
                            r"\1\3",
                            changed[prefix][i],
                        )
                        review[category].append(
                            stripped if stripped else changed[prefix][i]
                        )
                    if indicator[prefix][i] is not None:
                        ind = indicator[prefix][i].replace("?", " ", 1)
                        review[category].append(ind)
                    complete = True

                # clear the state
                changed[prefix] = []
                indicator[prefix] = []

            context = {}
            prev = None

            if complete:
                # separate next diff with a newline
                review[category].append("\n")

        elif kind in ("+", "-"):
            # store the changed line
            changed[kind].append(line)
            # store an empty change indicator line
            indicator[kind].append(None)
            prev = kind

        elif kind == "?":
            # remove the empty indicator line
            last = indicator[prev].pop()
            # verify that the indicator line is in fact empty
            if last is not None:
                die("popped %s", last)

            # store the actual indicator line
            indicator[prev].append(line)
            prev = None

        else:
            die("Unknown diff line: ", line)

    return review


def fmt_review(review: dict) -> None:
    for category in ["discuss", "comment", "nit"]:
        if review[category]:
            print("-" * 79)
            print(category.upper())
            print("-" * 79)
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
