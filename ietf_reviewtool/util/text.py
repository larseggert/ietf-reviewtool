"""ietf-reviewtool text module"""

import ipaddress
import logging
import re
import urllib.parse
import os

import textwrap
import urlextract  # type: ignore

from .docposition import SECTION_PATTERN
from .utils import TEST_NET_1, TEST_NET_2, TEST_NET_3, MCAST_TEST_NET, TEST_NET_V6

extractor = urlextract.URLExtract(extract_localhost=False, limit=9999999)
extractor.update_when_older(7)  # update TLDs when older than 7 days
extractor.add_enclosure("<", ">")
extractor.set_stop_chars_right(
    extractor.get_stop_chars_right()
    | {
        '"',
        "]",
        ">",
        ";",
        # ",",
        "'",
        ")",
    }
)


def normalize_ws(string: str) -> str:
    """
    Replace multiple white space characters by a single space.

    @param      string  The string to replace in

    @return     The replacement string
    """
    return re.sub(r"\s+", r" ", string)


def word_join(words: list, ox_comma=True, prefix="", suffix="") -> str:
    """
    Join list items using commas and "and", optionally each prefixed by something.

    @param      words     The words to join
    @param      ox_comma  Whether to use the oxford comma
    @param      prefix    A prefix to use for each word
    @param      suffix    A suffix to use for each word

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
        f'{suffix}{"," if ox_comma else ""} and {prefix}{words[-1]}{suffix}'
    )


def unfold(text: str) -> str:
    """
    Unfolds the paragraphs (i.e., removes hard line ends) in a text string.

    @param      text  The text to unfold

    @return     The unfolded version of the text.
    """

    def remove_spaces(match):
        if len(match.groups()) == 3:
            return match.group(1) + re.sub(r"\s+", "", match.group(2)) + match.group(3)
        return match.group(0)

    rand = r"bYYO2hxg2Bg4HhwEsbJQSSucukxfAbAIcDrPu5dw"

    folded = re.sub(r"[\r\f]", r"", text)
    folded = re.sub(r"\n{2,}\s*", rand, folded)
    folded = re.sub(r"^\s+", r"", folded, flags=re.MULTILINE)
    folded = re.sub(r"([\-/])\n([^\(])", r"\1\2", folded)
    folded = re.sub(r"\n", r" ", folded)
    folded = re.sub(rand, r"\n\n", folded)
    # remove newlines from URLs enclosed in <>
    folded = re.sub(r"(.*<)(\w*?://[^>]*?)(>.*)", remove_spaces, folded)
    return folded


def extract_ips(text: str) -> set:
    """
    Return a list of IP blocks in a text string.

    @param      text  The text to extract IP blocks from

    @return     List of IP blocks.
    """

    # find IPs not preceded by the word "section" (those are almost always false hits)
    ips = set(
        re.findall(
            r"""(?<![Ss]ection\s)\b(?:
             (?:[\da-f]{1,4}(?::[\da-f]{0,4})+)(?:/[\d]+)?|
             (?<!\d\.)(?:(?:\d{1,3}\.){3}\d{1,3}(?:/[\d\.]+)?(?!\.\d))|
             (?<!\d\.)(?:(?:\d{1,3}\.){0,3}\d{1,3}/[\d\.]+)
             )\b""",
            text,
            flags=re.IGNORECASE | re.VERBOSE,
        )
    )

    # find all section numbers and remove them from the set of hits
    sec_nrs = re.findall(r"^\d+(?:\.\d+)+", text, flags=re.MULTILINE)
    ips = {i for i in ips if i not in sec_nrs}

    # drop prefixes that do not contain at last one "." or at least two ":'", those are
    # almost always false hits
    ips = {i for i in ips if "/" not in i or "." in i or i.count(":") < 2}

    return ips


def extract_urls(
    text: str,
    log: logging.Logger,
    examples: bool = False,
    common: bool = False,
) -> dict[str, set[str]]:
    """
    Return a list of URLs in a text string.

    @param      text      The text to extract URLs from
    @param      log       The log
    @param      examples  Include example URLs
    @param      common    Include URLs that are common in IETF documents

    @return     List of URLs.
    """

    urls: dict[str, set] = {}
    for part, part_text in doc_parts(text).items():
        if part not in urls:
            urls[part] = set()

        # find all URLs in part
        part_text = unfold(part_text)
        try:
            extracted_urls = extractor.find_urls(
                text=part_text, with_schema_only=False, only_unique=True
            )
        except UnicodeDecodeError as err:
            log.warning("Could not extract URLs: %s", err)
            return {}
        for url in extracted_urls:
            url = url.rstrip(".\"]'>;,)")
            # urllib doesn't seem to support schemes that don't end in //, work around:
            fixed_url = re.sub(r"^(\w+:)([^/]{2}.*)", r"\1//\2", url, re.IGNORECASE)
            try:
                netloc = urllib.parse.urlparse(fixed_url).netloc
                if not netloc:
                    netloc = url
            except ValueError as err:
                log.warning("%s: %s", err, url)
                continue

            if not examples:
                # remove example URLs
                if re.search(
                    r"example\.(com|net|org)$|\.(test|example|invalid|localhost)$",
                    netloc,
                    re.IGNORECASE,
                ):
                    continue

                # remove URLs w/example IP addresses
                try:
                    addr = ipaddress.ip_address(netloc)
                    if (
                        isinstance(addr, ipaddress.IPv4Address)
                        and (
                            addr in TEST_NET_1
                            or addr in TEST_NET_2
                            or addr in TEST_NET_3
                            or addr in MCAST_TEST_NET
                        )
                    ) or (
                        isinstance(addr, ipaddress.IPv6Address) and addr in TEST_NET_V6
                    ):
                        continue
                except ValueError:
                    pass

            # remove some common URLs
            if not common and re.search(
                r"""https?://
                            datatracker\.ietf\.org/drafts/current/|
                            trustee\.ietf\.org/license-info|
                            (www\.)?rfc-editor\.org/(info|rfc)/rfc\d+|
                            (www\.)?ietf\.org/archive/id/draft-""",
                url,
                flags=re.VERBOSE | re.IGNORECASE,
            ):
                continue

            urls[part].add(url)

    return urls


def strip_pagination(text: str) -> str:
    """
    Strip headers and footers, end-of-line whitespace and CR/LF, similar to the rfcstrip
    tool (https://trac.tools.ietf.org/tools/rfcstrip/) from which the regexs used below
    were originally adopted.

    @param      text  The text of an RFC or Internet-Draft

    @return     The stripped version of the text.
    """
    stripped = ""
    new_page = False
    sentence = False
    have_blank = False
    for num, line in enumerate(text.split("\n")):
        # this doesn't always leave a blank line after a figure caption, improve?
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


def untag(tag: str) -> str:
    """
    Remove angle brackets from reference tag.

    @param      tag   Reference tag

    @return     Tag without angle brackets.
    """
    return re.sub(r"^\[(.*)\]$", r"\1", tag)


def basename(item: str) -> str:
    """
    Return the base name of a given item by stripping the path and the extension.

    @param      item  The item to return the base name for

    @return     The base name of the item
    """
    item = os.path.splitext(os.path.basename(item))[0]
    rev = revision(item)
    return item.removesuffix("-" + rev)


def revision(item: str) -> str:
    """
    Return the revision number of a given item by stripping the path, the name
    and the txt suffix.

    @param      item  The item to return the base name for

    @return     The base name of the item
    """
    result = re.search(r".*-(\d+)(?:\.\w+)?$", item)
    return result.group(1) if result else ""


def wrap_para(text: str, end: str, width: int) -> str:
    """
    Return a wrapped version of the text, ending with end.

    @param      text   The text to wrap
    @param      end    The end to add to the text

    @return     Wrapped version of text followed by end.
    """
    return (
        textwrap.fill(text, width=width, break_on_hyphens=False, break_long_words=False)
        + end
    )


def undo_rfc8792(text: str) -> str:
    """
    Undo RFC 8792 single backslash strategy line-wrapping.

    @param      text  The text to unwrap

    @return     The unwrapped text.
    """
    # TODO: add support for double backslash strategy
    return re.sub(r"\\$\n^\s*", "", text, flags=re.MULTILINE)


def doc_parts(text: str) -> dict[str, str]:
    """
    Split document lines into body text and reference sections.

    @param      text  The text to spit

    @return     A dict containing the lines in different parts of the document.
    """
    parts = {"text": "", "informative": "", "normative": ""}
    part = "text"
    for line in text.splitlines(keepends=True):
        pot_sec = SECTION_PATTERN.search(line)
        if pot_sec:
            which = pot_sec.group(0)
            if re.search(
                r"^(?:(\d\.?)+\s+)?(?:Non-Norm|Inform)(?:ative|ational)\s+References?\s*$",
                which,
                flags=re.IGNORECASE,
            ):
                part = "informative"
            elif re.search(
                r"^(?:(\d\.?)+\s+)?(Normative\s+)?References?\s*$",
                which,
                flags=re.IGNORECASE,
            ):
                part = "normative"
            else:
                part = "text"
        parts[part] += line
    return parts
