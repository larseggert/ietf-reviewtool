#! /usr/bin/env python3

"""
Review tool for IETF documents.
"""

import argparse
import json
import logging
import os
import re
import urllib.error
import urllib.request


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

        logging.info("Downloading %s", item)
        if item.startswith("draft-"):
            url = "https://www.ietf.org/archive/id/" + file_name
        elif item.startswith("rfc"):
            url = "https://rfc-editor.org/rfc/" + file_name
        elif item.startswith("charter-"):
            url_pattern = re.sub(
                r"(.*)(((-[0-9]+){2}).txt)$", r"\1/withmilestones\2", file_name
            )
            url = datatracker + "/doc/" + url_pattern
            strip = False  # don't strip charters
        text = fetch_url(url)
        if strip:
            logging.debug("Stripping %s", item)
            text = strip_pagination(text)
        if text is not None:
            file = open(file_name, "w")
            file.write(text)
            file.close()


def strip_items(items: list, in_place: bool = False) -> None:
    """
    Run strip_pagination over the named items

    @param      items  The items to strip.

    @return     -
    """
    logging.debug(items)
    for item in items:
        if not os.path.isfile(item):
            logging.warning("%s does not exist, skipping", item)
            continue

        file = open(item, "r")
        text = strip_pagination(file.read())
        file.close()

        if text is not None:
            if not in_place:
                item += ".stripped"
                if os.path.isfile(item):
                    logging.warning("%s exists, skipping", item)
                    continue

            logging.debug("Saving stripped version as %s", item)
            file = open(item, "w")
            file.write(text)
            file.close()


def main() -> None:
    """
    Parse options and execute things.

    @return     -
    """
    main_parser = argparse.ArgumentParser(
        description=("Review tool for IETF documents.")
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

    for parser in [parser_fetch, parser_strip]:
        parser.add_argument(
            "items",
            metavar="item",
            nargs="+",
            help="names of items to " + parser.prog,
        )

    args = main_parser.parse_args()
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
            agenda_file = "agenda.json"
            file = open(agenda_file, "w")
            file.write(json.dumps(agenda, indent=4))
            file.close()

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


if __name__ == "__main__":
    main()
