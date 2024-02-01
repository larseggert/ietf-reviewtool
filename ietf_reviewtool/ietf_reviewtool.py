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

import difflib
import html
import ipaddress
import json
import json5  # type: ignore
import logging
import os
import re
import xml.etree.ElementTree

from typing import Union

import click

from .agenda import get_current_agenda, get_items_on_agenda
from .boilerplate import check_tlp, check_boilerplate
from .grammar import check_grammar
from .inclusive import check_inclusivity
from .metadata import check_meta
from .references import check_refs
from .review import IetfReview
from .doc import Doc

from .util.fetch import fetch_url, fetch_dt, get_items
from .util.text import (
    word_join,
    extract_ips,
    extract_urls,
    strip_pagination,
    unfold,
    undo_rfc8792,
    doc_parts,
)
from .util.utils import (
    read,
    write,
    TEST_NET_1,
    TEST_NET_2,
    TEST_NET_3,
    MCAST_TEST_NET,
    TEST_NET_V6,
)


log = logging.getLogger(__name__)


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
def cli(
    ctx: click.Context, datatracker: str, verbose: int, default: bool, width: int
) -> None:
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
    urls: dict[str, set] = {}
    for item in items:
        if not os.path.isfile(item):
            log.warning("%s does not exist, skipping", item)
            continue

        log.debug("Extracting URLs from %s", item)
        text = strip_pagination(read(item, log))

        if text:
            item_urls = extract_urls(read(item, log), log, examples, common)
            for part, part_urls in item_urls.items():
                if part not in urls:
                    urls[part] = set()
                urls[part] |= item_urls[part]

    for part, part_urls in urls.items():
        for url in part_urls:
            print(url, part)


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
    state: State,
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
    @param      extract_markdown  Whether to attempt to extract Markdown from fetched
                                  XML
    """
    get_items(
        list(items),
        log,
        state.datatracker,
        strip,
        fetch_writeups,
        fetch_xml,
        extract_markdown,
    )


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
    @param      in_place  Whether to overwrite the item, or save a ".stripped" copy.

    @return     -
    """
    for item in items:
        if not os.path.isfile(item):
            log.warning("%s does not exist, skipping", item)
            continue

        text = strip_pagination(read(item, log))
        if not text:
            return

        if not in_place:
            item += ".stripped"
            if os.path.isfile(item):
                log.warning("%s exists, skipping", item)
                continue

        log.debug("Saving stripped version as %s", item)
        write(text, item)


def thank_art_reviewer(
    doc: Doc, review: IetfReview, thank_art: str, datatracker: str
) -> None:
    """
    Add a thank-you note to the member of the indicated review team.

    @param      doc          The document text
    @param      review       IETF Review object
    @param      thank_art    The acronym of a review team
    @param      datatracker  The datatracker URL

    @return     None
    """
    art_reviews = fetch_dt(
        datatracker,
        "doc/reviewassignmentdocevent/?doc__name=" + doc.name,
        log,
    )
    if not art_reviews:
        log.warning("Could not fetch ART reviews for %s", doc.name)
        return

    thanked = set()
    for rev_assignment in art_reviews:
        if rev_assignment["type"] != "closed_review_assignment":
            continue

        assignment = fetch_dt(
            datatracker,
            rev_assignment["review_assignment"],
            log,
        )

        if not assignment:
            log.warning("Could not fetch review_assignment for %s", doc.name)
            continue

        reviewer = fetch_dt(datatracker, assignment["reviewer"], log)

        if not reviewer:
            log.warning("Could not fetch reviewer for %s", doc.name)
            continue

        reviewer = fetch_dt(datatracker, reviewer["person"], log)

        if not reviewer:
            log.warning("Could not fetch reviewer for %s", doc.name)
            continue

        if assignment["state"].endswith("rejected/"):
            log.debug("Review for %s was rejected", doc.name)
            continue

        if assignment["state"].endswith("no-response/"):
            log.debug("Review for %s was not completed", doc.name)
            continue

        if assignment["state"].endswith("withdrawn/"):
            log.debug("Review for %s was withdrawn", doc.name)
            continue

        if not assignment["review"]:
            log.warning("Could not fetch review for %s", doc.name)
            continue

        art_review = fetch_dt(datatracker, assignment["review"], log)

        if not art_review:
            log.warning("Could not fetch review for %s", doc.name)
            continue

        group = fetch_dt(datatracker, art_review["group"], log)

        if not group:
            log.warning("Could not fetch ART for %s", doc.name)
            continue

        if reviewer["id"] in thanked:
            log.warning(
                "Already recorded %s for %s review", reviewer["name"], group["name"]
            )
            continue

        if group["acronym"].lower() == thank_art.lower():
            # remember we thanked for this
            thanked.add(reviewer["id"])

            review.preface(
                "",
                f'Thanks to {reviewer["name"] or reviewer["name_from_draft"]} '
                + f'for the {group["name"]} review ({art_review["external_url"]}).',
            )


def check_ips(doc: Doc, review: IetfReview, verbose: bool) -> None:
    """
    Check the IP addresses and blocks in the document.

    @param      doc      The document text
    @param      review   IETF Review object
    @param      verbose  Whether to include debug information

    @return     None
    """
    result: list[
        Union[
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network,
        ]
    ] = []
    faulty = []
    for ip_literal in extract_ips(doc.orig):
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

    quote = "`" if review.mkd else '"'
    if faulty and verbose:
        msg = "Unparsable possible IP "
        if len(faulty) > 1:
            msg += "blocks or addresses: "
        else:
            msg += "block or address: "
        msg += word_join(faulty, prefix=quote, suffix=quote) + "."
        review.nit("IP addresses", msg)

    faulty = []
    for ip_obj in result:
        if isinstance(ip_obj, ipaddress.IPv4Address) and (
            ip_obj in TEST_NET_1
            or ip_obj in TEST_NET_2
            or ip_obj in TEST_NET_3
            or ip_obj in MCAST_TEST_NET
        ):
            continue

        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in TEST_NET_V6:
            continue

        if isinstance(ip_obj, ipaddress.IPv4Network) and (
            ip_obj.subnet_of(TEST_NET_1)
            or ip_obj.subnet_of(TEST_NET_2)
            or ip_obj.subnet_of(TEST_NET_3)
            or ip_obj.subnet_of(MCAST_TEST_NET)
        ):
            continue

        if isinstance(ip_obj, ipaddress.IPv6Network) and ip_obj.subnet_of(TEST_NET_V6):
            continue

        faulty.append(str(ip_obj))

    if faulty:
        msg = "Found IP "
        if len(faulty) > 1:
            msg += "blocks or addresses"
        else:
            msg += "block or address"
        msg += " not inside RFC5737/RFC3849 example ranges: "
        msg += word_join(faulty, prefix=quote, suffix=quote) + "."
        review.comment("IP addresses", msg)


def check_html_entities(doc: Doc, review: IetfReview) -> None:
    """
    Warn if the document contains HTML entities.

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    unescaped = html.unescape(doc.orig)
    if doc.orig != unescaped:
        entities = []
        diff = list(
            difflib.ndiff(
                doc.orig_lines,
                unescaped.splitlines(keepends=True),
                linejunk=None,
                charjunk=None,
            )
        )
        for line in diff:
            if re.search(r"^- ", line):
                entities.extend(re.findall(r"(&#?\w+;)", line, flags=re.IGNORECASE))

        if entities:
            quote = "`" if review.mkd else '"'
            review.nit(
                "Stray characters",
                "The text version of this document contains these HTML entities, "
                "which might indicate issues with its XML source: "
                f"{word_join(list(set(entities)), prefix=quote, suffix=quote)}",
            )


def check_urls(doc: Doc, review: IetfReview, verbose: bool) -> None:
    """
    Check the reachability and various other aspects of URLs in the document/

    @param      doc      The document text
    @param      review   IETF Review object
    @param      verbose  Whether to be verbose during the checks

    @return     None
    """
    result = []
    urls = set()
    for part, part_urls in extract_urls(doc.orig, log).items():
        urls |= part_urls

    for url in urls:
        if re.search(r"tools\.ietf\.org", url, flags=re.IGNORECASE):
            result.append(url)

    if result:
        review.nit_bullets(
            "URLs",
            "These URLs point to tools.ietf.org, which has been taken out of service:",
            result,
        )
        urls -= set(result)

    result = []
    for url in urls:
        if not re.search(r"^https?:", url, flags=re.IGNORECASE):
            result.append(url)

    if result:
        review.nit_bullets("URLs", "Found non-HTTP URLs in the document:", result)

    reachability = {u: fetch_url(u, log, verbose, "HEAD") for u in urls}
    result = []
    for url in urls:
        if reachability[url] == "":
            result.append(url)

    if result:
        review.nit_bullets(
            "URLs", "These URLs in the document did not return content:", result
        )

    result = []
    for url in urls:
        if url.startswith("https:"):
            continue
        if reachability[url] is not None:
            test_url = re.sub(r"^\w+:", r"https:", url)
            if fetch_url(test_url, log, verbose, "HEAD"):
                result.append(url)

    if result:
        review.nit_bullets(
            "URLs",
            "These URLs in the document can probably be converted to HTTPS:",
            result,
        )


def check_expert_review(doc: Doc, review: IetfReview) -> None:
    """
    Check whether the document mentions "Expert Review" or "Specification Required" and
    add a note to check whether this IANA policy seems reasonable.

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    if re.search(
        r"(\bExpert\s+Review\b|Specification\s+Required)",
        unfold(doc.orig),
        flags=re.IGNORECASE,
    ):
        review.comment(
            "Note to self",
            "Check whether Expert Review is an appropriate registration policy here.",
        )


def check_implementation_status(doc: Doc, review: IetfReview) -> None:
    """
    Check whether the "Implementation Status" section is reasonable.

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    if re.search(r"\bImplementation\s+Status\b", unfold(doc.orig), flags=re.IGNORECASE):
        review.comment(
            "Note to self",
            'Check whether the "Implementation Status" section is reasonable.',
        )


def check_code(doc: Doc, review: IetfReview) -> None:
    """
    Check any code in "CODE BEGINS/CODE ENDS" blocks.

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    # this assumes the JSON is properly indented
    snippets = re.finditer(r"<CODE BEGINS>(.*)<CODE ENDS>", doc.orig, flags=re.DOTALL)

    for snip in snippets:
        text = snip.group(1)
        # try and figure out what the code is in
        file = re.search(r"\s*file\s*['\"](.*)['\"]\s*$", text, flags=re.MULTILINE)
        lang = None
        if file:
            text = "".join(text.splitlines(keepends=True)[1:])
            lang = os.path.splitext(file.group(1))[1][1:].lower().strip()
        # TODO: validate


def check_json(doc: Doc, review: IetfReview) -> None:
    """
    Check any JSON in the document for issues.

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    snippets = re.finditer(r"^(\s*){\s*$", doc.orig, flags=re.MULTILINE)
    for snip in snippets:
        # parse JSON snippet until closing brace
        try:
            tokens = list(json5.tokenizer.tokenize(doc.orig[snip.start() :]))
        except json5.utils.JSON5DecodeError as err:
            msg = f"{str(err)}\n"
            index_match = re.search(r"index (\d+)", msg)
            if index_match:
                index = int(index_match.groups()[0]) + 1
                msg += f"```{doc.orig[snip.start() : snip.start() + index]}\n```\n"
            review.nit("JSON", msg, wrap=False)
            return
        stack = []
        collected = []
        for token in tokens:
            collected.append(token.value)
            if token.type in ["WHITESPACE"]:
                continue
            if token.type in ["LBRACE", "LBRACKET"]:
                stack.append(token)
            elif token.type in ["RBRACE", "RBRACKET"]:
                stack.pop()
            if not stack:
                break

        text = "".join(collected)
        # fix it up a bit
        text = undo_rfc8792(text.replace("base64url({", "{").replace("})", "}"))
        try:
            json.loads(text)
        except json.decoder.JSONDecodeError as err:
            nit = ""
            quote = "> "
            if review.mkd:
                nit += "```\n"
                quote = ""

            for i, l in enumerate(text.splitlines(keepends=True)):
                nit += f"{quote}{l}"
                if i == err.lineno - 2:
                    nit += f"{quote}{' ' * (err.colno - 1)}^ {err.msg}\n"

            if review.mkd:
                nit += "```\n"

            review.nit("JSON", nit, wrap=False)


def check_xml(doc: Doc, review: IetfReview) -> None:
    """
    Check any XML in the document for issues

    @param      doc     The document text
    @param      review  IETF Review object

    @return     None
    """
    snippets = re.finditer(r"^(.*)<\?xml\s", doc.orig, flags=re.MULTILINE)
    for snip in snippets:
        start = re.search(r"<\s*([\w:-]+)", doc.orig[snip.start() :])
        if not start:
            log.warning("cannot find an XML start tag")
            continue

        end = re.search(
            r"</\s*" + re.escape(start.group(1)) + r"\s*>", doc.orig[snip.start() :]
        )
        if not end:
            log.warning('cannot find XML end tag "%s"', start.group(1))
            continue

        text = undo_rfc8792(doc.orig[snip.start() : snip.start() + end.end()])

        if snip.group(1):
            prefix = snip.group(1)
            # log.debug('XML prefix "%s"', prefix)
            text = re.sub(r"^" + re.escape(prefix), r"", text, flags=re.MULTILINE)

        try:
            xml.etree.ElementTree.fromstring(text)
        except xml.etree.ElementTree.ParseError as err:
            review.nit(
                "XML", f'XML issue: "{err}"\n> {text[err.position[0] - 2]}\n', False
            )


def validate_gh_id(_ctx, _param, value):
    """
    Validate the --github-id parameter. See
    https://click.palletsprojects.com/en/8.1.x/options/#callbacks-for-validation

    @param      _ctx    The context
    @param      _param  The parameter
    @param      value   The value

    @return     The value
    """
    if isinstance(value, tuple):
        return value
    if value != "" and not re.match(r"@\w+", value):
        raise click.BadParameter("GitHub user ID must be in the form '@username'")
    return value


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
@click.option(
    "--output-markdown",
    "gen_mkd",
    is_flag=True,
    help=(
        "Generate review in IETF Comments Markdown Format. "
        "See https://github.com/mnot/ietf-comments/blob/main/format.md"
    ),
)
@click.option(
    "--role",
    "role",
    default="GEN AD",
    help="Indicate the role you are reviewing this document in (if any).",
)
@click.option(
    "--github-id",
    "gh_id",
    default="@larseggert",
    callback=validate_gh_id,
    help='Your GitHub ID ("@username").',
)
@click.pass_obj
def review_items(
    state: State,
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
    gen_mkd: bool,
    role: str,
    gh_id: str,
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

        doc = Doc(item, log, state.datatracker)
        review = IetfReview(doc, gen_mkd, role.strip(), gh_id.strip(), state.width)

        if chk_boilerpl and doc.is_id:
            check_boilerplate(doc, review)

        if chk_meta and doc.meta:
            check_meta(doc, review, state.datatracker, log)

        if chk_misc:
            check_html_entities(doc, review)

        if chk_tlp:
            check_tlp(doc, review)

        check_xml(doc, review)
        check_json(doc, review)
        check_code(doc, review)
        check_expert_review(doc, review)
        check_implementation_status(doc, review)

        verbose = state.verbose > 0

        if chk_refs and doc.is_id:
            check_refs(doc, review, state.datatracker, log)

        if chk_urls:
            check_urls(doc, review, verbose)

        if chk_inclusiv:
            check_inclusivity(doc, review, log, verbose)

        if chk_ips:
            check_ips(doc, review, verbose)

        thank_art_reviewer(doc, review, thank_art, state.datatracker)

        if doc.name.startswith("charter-"):
            review.comment("Note to self", "Ask about any chair changes.")

        if chk_grammar:
            check_grammar(
                doc.current_lines, grammar_skip_rules, review, state.width, verbose
            )

        if gen_mkd:
            review.note(
                "",
                'This review is in the ["IETF Comments" Markdown format][ICMF], '
                "You can use the [`ietf-comments` tool][ICT] to automatically convert "
                "this review into individual GitHub issues. Review generated by the "
                "[`ietf-reviewtool`][IRT].",
            )
            review.note(
                "",
                "[ICMF]: https://github.com/mnot/ietf-comments/blob/main/format.md\n"
                "[ICT]: https://github.com/mnot/ietf-comments\n"
                "[IRT]: https://github.com/larseggert/ietf-reviewtool\n",
                wrap=False,
            )

        print(review)


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
    state: State,
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
    @param      extract_markdown  Whether to attempt to extract Markdown from XML
                                  sources
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
        log,
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
