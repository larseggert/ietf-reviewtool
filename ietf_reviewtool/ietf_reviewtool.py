#! /usr/bin/env python3

"""
Review tool for IETF documents.

Copyright (C) 2021-2022  Lars Eggert

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

import base64
import difflib
import gzip
import html
import ipaddress
import json
import logging
import os
import re
import tempfile
import xml.etree.ElementTree

import click

from .agenda import get_current_agenda, get_items_on_agenda
from .boilerplate import check_tlp, check_boilerplate
from .grammar import check_grammar
from .inclusive import check_inclusivity
from .metadata import check_meta
from .references import check_refs

from .util.fetch import (
    fetch_url,
    fetch_dt,
    fetch_meta,
    fetch_init_cache,
    get_writeups,
)
from .util.format import fmt_nit, fmt_comment, fmt_review
from .util.text import (
    word_join,
    wrap_para,
    unfold,
    extract_ips,
    extract_urls,
    basename,
    strip_pagination,
    section_and_paragraph,
    get_status,
    get_relationships,
    extract_refs,
)
from .util.utils import read, write


log = logging.getLogger(__name__)


TEST_NET_1 = ipaddress.ip_network("192.0.2.0/24")
TEST_NET_2 = ipaddress.ip_network("198.51.100.0/24")
TEST_NET_3 = ipaddress.ip_network("203.0.113.0/24")
MCAST_TEST_NET = ipaddress.ip_network("233.252.0.0/24")
TEST_NET_V6 = ipaddress.ip_network("2001:db8::/32")


class State:
    """
    This class describes the global state.
    """

    def __init__(self, datatracker=None, verbose=0, default=True, width=79):
        self.datatracker = datatracker
        self.verbose = verbose
        self.width = width
        self.default = default


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], show_default=True)


@click.group(help="Review tool for IETF documents.", context_settings=CONTEXT_SETTINGS)
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
def cli(ctx: object, datatracker: str, verbose: int, default: bool, width: int) -> None:
    """
    Do some initialization

    @param      ctx          The context object
    @param      datatracker  The datatracker URL to use
    @param      verbose      Whether to be (very) verbose during operation
    @param      default      Whether all checks are enabled as a default
    @param      width        The character width any output should be wrapped to
    """
    datatracker = re.sub(r"/+$", "", datatracker)
    ctx.obj = State(datatracker, verbose, default, width)
    log.setLevel(logging.INFO if verbose == 0 else logging.DEBUG)
    fetch_init_cache(log)


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
    """
    Extract URLs from items.

    @param      items     The items to extract URLs from.
    @param      examples  Include "example" URLs (e.g., to example.com, etc.)
    @param      common    Include "common" URLs (e.g., to rfc-editor.org)
    """
    urls = set()
    for item in items:
        if not os.path.isfile(item):
            log.warning("%s does not exist, skipping", item)
            continue

        log.debug("Extracting URLs from %s", item)
        text = strip_pagination(read(item, log))

        if text is not None:
            urls |= extract_urls(read(item, log), log, examples, common)

    for url in urls:
        print(url)


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
@click.option(
    "--fetch-xml/--no-fetch-xml",
    "fetch_xml",
    default=True,
    help="Fetch XML source of item, if available.",
)
@click.option(
    "--extract-markdown/--no-extract-markdown",
    "extract_markdown",
    default=True,
    help="Extract Markdown source from XML source, if possible.",
)
@click.pass_obj
def fetch(
    state: object,
    items: list,
    strip: bool,
    fetch_writeups: bool,
    fetch_xml: bool,
    extract_markdown: bool,
) -> None:
    """
    Fetch items.

    @param      state             The global program state
    @param      items             The names of items to fetch
    @param      strip             Whether to strip the fetched items
    @param      fetch_writeups    Whether to also fetch related writeups
    @param      fetch_xml         Whether to also fetch XML sources
    @param      extract_markdown  Whether to attempt to extract Markdown from
                                  fetched XML
    """
    get_items(
        items,
        state.datatracker,
        strip,
        fetch_writeups,
        fetch_xml,
        extract_markdown,
    )


def get_items(
    items: list,
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
        text = None
        url = None
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
            doc = re.sub(which + r"-(.*)", r"draft-\1", item)
            text = get_writeups(datatracker, doc, log)
            # in-progress conflict-reviews/status-changes are not in the cache
            doc = basename(doc)
            slug = "conflrev" if which == "conflict-review" else "statchg"
            target = fetch_dt(
                datatracker,
                f"doc/relateddocument/?relationship__slug={slug}&target__name=" + doc,
                log,
            )
            if not target:
                log.warning("cannot find target for %s", doc)
                continue
            docalias = fetch_dt(datatracker, target[0]["target"], log)
            if not docalias:
                log.warning("cannot find docalias for %s", target[0]["target"])
                continue
            doc = fetch_dt(datatracker, docalias["document"], log)
            if not doc:
                log.warning("cannot find doc for %s", docalias["document"])
                continue
            items.append(f"{doc['name']}-{doc['rev']}.txt")
            do_strip = False
        # else:
        #     die(f"Unknown item type: {item}", log)

        if cache is not None:
            cache_file = os.path.join(cache, file_name)
            if os.path.isfile(cache_file):
                log.debug("Using cached %s", item)
                text = read(cache_file, log)
            else:
                log.debug("No cached copy of %s in %s", item, cache)

        if text is None and url is not None:
            text = fetch_url(url, log)

        if text is not None:
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


@click.command("strip", help="Strip headers, footers and pagination from items.")
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

        text = strip_pagination(read(item, log))

        if text is not None:
            if not in_place:
                item += ".stripped"
                if os.path.isfile(item):
                    log.warning("%s exists, skipping", item)
                    continue

            log.debug("Saving stripped version as %s", item)
            write(text, item)


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
        # print(cur, end="")
        kind = cur[0]

        nxt = diff[num + 1] if num < len(diff) - 1 else None
        nxt_kind = nxt[0] if nxt else None

        if cur in ["+ \n", "- \n"]:
            prev = kind
            if nxt:
                continue

        if kind in ["+", "-"] and nxt_kind == "?":
            changed[kind].append(cur)

        elif kind == "?" and prev in ["+", "-"]:
            indicator[prev].append(cur)

        elif kind in ["-"]:  # this would catch nits: ["+", "-"]:
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

        elif not nxt and kind != " ":
            changed[kind].append(cur)

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


def gather_comments(diff: list, width: int) -> dict:
    """
    Return a dict that contains lists of all comments of all categories.

    @param      diff   A diff with nits removed (by strip_nits_from_diff)
    @param      width  The width to wrap to

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
                result[item["cat"]].extend(fmt_comment(item, para_sec, width))
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
                result[item["cat"]].extend(fmt_comment(item, para_sec, width))

        para_sec = section_and_paragraph(nxt, cur, para_sec)

    return result


def review_item(orig: list, rev: list, width: int = 79) -> dict:
    """
    Calculates a diff between orig and rev.

    @param      orig   The original text
    @param      rev    The revised text
    @param      width  The width to wrap to

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
    review = gather_comments(diff, width)
    review["nit"].extend(nits)
    return review


def check_xml(doc: str) -> None:
    """
    Check any XML in the document for issues

    @param      doc   The document text

    @return     List of issues found
    """
    result = {"discuss": [], "comment": [], "nit": []}
    snippets = re.finditer(r"^(.*)<\?xml\s", doc, flags=re.MULTILINE)
    for snip in snippets:
        start = re.search(r"<\s*([\w:]+)", doc[snip.start() :])
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
            text = re.sub(r"^" + re.escape(prefix), r"", text, flags=re.MULTILINE)

        try:
            xml.etree.ElementTree.fromstring(text)
        except xml.etree.ElementTree.ParseError as err:
            text = text.splitlines(keepends=True)
            print(text[err.position[0] - 2])
            result["nit"].append(
                f'XML issue: "{err}":\n> {text[err.position[0] - 2]}\n'
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
    "--check-ips/--no-check-ips",
    "chk_ips",
    default=None,
    help="Check IP address ranges.",
)
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
@click.option(
    "--thank-art",
    "thank_art",
    default="genart",
    help="Generate a thank-you for the given Area Review Team reviewer.",
)
@click.pass_obj
def review_items(
    state: object,
    items: list,
    chk_urls: bool,
    chk_ips: bool,
    chk_refs: bool,
    chk_grammar: bool,
    chk_meta: bool,
    chk_inclusiv: bool,
    chk_boilerpl: bool,
    chk_misc: bool,
    chk_tlp: bool,
    thank_art: str,
    grammar_skip_rules: str,
) -> None:
    """
    Extract reviews from named items.

    @param      items        The items to extract reviews from
    @param      datatracker  The datatracker URL to use
    @param      chk_urls     Whether to check URLs for reachability

    @return     -
    """

    chk_ips = state.default if chk_ips is None else chk_ips
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
                orig = read(orig_item, log)
                os.chdir(current_directory)
            rev = read(item, log)
            if orig is None:
                log.error(
                    "No original for %s, cannot review, " "only performing checks",
                    item,
                )
                orig = rev
            orig_lines = orig.splitlines(keepends=True)
            rev = rev.splitlines(keepends=True)
            review = review_item(orig_lines, rev, width=state.width)
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
                                re.findall(r"(&#?\w+;)", line, flags=re.IGNORECASE)
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
                review_extend(review, check_boilerplate(orig, status, state.width))

            if chk_tlp:
                review_extend(review, check_tlp(orig, status, state.width))

            meta = fetch_meta(state.datatracker, name, log)
            if chk_meta and meta:
                review_extend(
                    review,
                    check_meta(state.datatracker, orig, meta, state.width, log),
                )

            # check_xml(orig)
            review_extend(review, check_xml("".join(rev)))

            verbose = state.verbose > 0
            if chk_grammar:
                review_extend(
                    review,
                    check_grammar(rev, grammar_skip_rules, state.width, verbose),
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
                        log,
                    ),
                )

            if chk_urls:
                result = []
                urls = extract_urls(orig, log)

                for url in urls:
                    if re.search(r"://tools\.ietf\.org", url, flags=re.IGNORECASE):
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
                    if not re.search(r"^https?:", url, flags=re.IGNORECASE):
                        result.append(url)

                if result:
                    review["nit"].append(
                        "Found non-HTTP URLs in the document:\n",
                    )
                    review["nit"].extend(f" * {line}\n" for line in result)
                    review["nit"].append("\n")

                reachability = {u: fetch_url(u, log, verbose, "HEAD") for u in urls}
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
                        if fetch_url(test_url, log, verbose, "HEAD") is not None:
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
                    check_inclusivity(unfold("".join(rev)), state.width, verbose),
                )

            art_reviews = fetch_dt(
                state.datatracker,
                "doc/reviewassignmentdocevent/?doc__name=" + name,
                log,
            )

            if chk_ips:
                result = []
                faulty = []
                for ip_literal in extract_ips(orig):
                    if "/" in ip_literal:
                        try:
                            result.append(ipaddress.ip_network(ip_literal))
                        except ValueError:
                            faulty.append(str(ip_literal))
                    else:
                        try:
                            result.append(ipaddress.ip_address(ip_literal))
                        except ValueError:
                            faulty.append(str(ip_literal))

                if faulty:
                    msg = "Unparsable possible IP "
                    if len(faulty) > 1:
                        msg += "blocks or addresses: "
                    else:
                        msg += "block or address: "
                    msg += word_join(faulty, prefix='"', suffix='"') + "."
                    review["nit"].append(wrap_para(msg))

                faulty = []
                for ip_obj in result:
                    if isinstance(ip_obj, ipaddress.IPv4Address) and (
                        ip_obj in TEST_NET_1
                        or ip_obj in TEST_NET_2
                        or ip_obj in TEST_NET_3
                        or ip_obj in MCAST_TEST_NET
                    ):
                        continue

                    if (
                        isinstance(ip_obj, ipaddress.IPv6Address)
                        and ip_obj in TEST_NET_V6
                    ):
                        continue

                    if isinstance(ip_obj, ipaddress.IPv4Network) and (
                        ip_obj.subnet_of(TEST_NET_1)
                        or ip_obj.subnet_of(TEST_NET_2)
                        or ip_obj.subnet_of(TEST_NET_3)
                        or ip_obj.subnet_of(MCAST_TEST_NET)
                    ):
                        continue

                    if isinstance(ip_obj, ipaddress.IPv6Network) and ip_obj.subnet_of(
                        TEST_NET_V6
                    ):
                        continue

                    faulty.append(str(ip_obj))

                if faulty:
                    msg = "Found IP "
                    if len(faulty) > 1:
                        msg += "blocks or addresses"
                    else:
                        msg += "block or address"
                    msg += " not inside RFC5737/RFC3849 example ranges: "
                    msg += word_join(faulty, prefix='"', suffix='"') + "."
                    review["comment"].append(wrap_para(msg))

            if art_reviews:
                for rev_assignment in art_reviews:
                    if rev_assignment["type"] != "closed_review_assignment":
                        continue

                    assignment = fetch_dt(
                        state.datatracker,
                        rev_assignment["review_assignment"],
                        log,
                    )

                    if not assignment:
                        log.warning("Could not fetch review_assignment for %s", name)
                        continue

                    reviewer = fetch_dt(state.datatracker, assignment["reviewer"], log)

                    if not reviewer:
                        log.warning("Could not fetch reviewer for %s", name)
                        continue

                    reviewer = fetch_dt(state.datatracker, reviewer["person"], log)

                    if not reviewer:
                        log.warning("Could not fetch reviewer for %s", name)
                        continue

                    if assignment["state"].endswith("rejected/"):
                        log.debug("Review for %s was rejected", name)
                        continue

                    if assignment["state"].endswith("no-response/"):
                        log.debug("Review for %s was not completed", name)
                        continue

                    if assignment["state"].endswith("withdrawn/"):
                        log.debug("Review for %s was withdrawn", name)
                        continue

                    art_review = fetch_dt(state.datatracker, assignment["review"], log)

                    if not art_review:
                        log.warning("Could not fetch review for %s", name)
                        continue

                    group = fetch_dt(state.datatracker, art_review["group"], log)

                    if not group:
                        log.warning("Could not fetch ART for %s", name)
                        continue

                    if group["acronym"].lower() == thank_art.lower():
                        review["comment"].append(
                            wrap_para(
                                "Thanks to "
                                + (reviewer["name_from_draft"] or reviewer["name"])
                                + f" for their {group['name']} review "
                                f"({art_review['external_url']})."
                            )
                        )

            else:
                log.warning("Could not fetch ART reviews for %s", name)

            if name.startswith("charter-"):
                review["comment"].append(
                    "Note to self: Ask about any chair changes.\n\n",
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
@click.option(
    "--fetch-xml/--no-fetch-xml",
    "fetch_xml",
    default=True,
    help="Fetch XML source of item, if available.",
)
@click.option(
    "--extract-markdown/--no-extract-markdown",
    "extract_markdown",
    default=True,
    help="Extract Markdown source from XML source, if possible.",
)
@click.pass_obj
def fetch_agenda(
    state: object,
    mkdir,
    save_agenda,
    strip,
    fetch_writeups,
    fetch_xml,
    extract_markdown,
):
    """
    Fetches all items on the next telechat agenda.

    @param      state             The global program state
    @param      mkdir             Whether to create a directory
    @param      save_agenda       Whether to save the agenda JSON
    @param      strip             Whether to strip fetched agenda items
    @param      fetch_writeups    Whether to also fetch related writeups
    @param      fetch_xml         Whether to also fetch XML sources of items
    @param      extract_markdown  Whether to attempt to extract Markdown from
                                  XML sources
    """
    agenda = get_current_agenda(state.datatracker, log)
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

    gotten = get_items(
        items,
        state.datatracker,
        strip,
        fetch_writeups,
        fetch_xml,
        extract_markdown,
    )
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
