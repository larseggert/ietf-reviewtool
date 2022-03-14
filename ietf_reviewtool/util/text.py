import logging
import re
import textwrap
import urllib.parse

import urlextract

from .patterns import SECTION_PATTERN


def normalize_ws(string: str) -> str:
    """
    Replace multiple white space characters by a single space.

    @param      string  The string to replace in

    @return     The replacement string
    """
    return re.sub(r"\s+", r" ", string)


def word_join(words: list, ox_comma=True, prefix="", suffix="") -> str:
    """
    Join list items using commas and "and", optionally each prefixed by
    something.

    @param      words         The words to join
    @param      ox_comma      Whether to use the oxford comma
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
        f'{suffix}{"," if ox_comma else ""} and {prefix}{words[-1]}{suffix}'
    )


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
    #     r"([^a-z\d])([a-z]{2,})://", r"\1\2://", folded, flags=re.IGNORECASE
    # )
    folded = re.sub(r"([\-/])\n([^\(])", r"\1\2", folded)
    folded = re.sub(r"\n", r" ", folded)
    folded = re.sub(rand, r"\n\n", folded)

    return folded


def extract_ips(text: str) -> set:
    """
    Return a list of IP blocks in a text string.

    @param      text  The text to extract IP blocks from

    @return     List of IP blocks.
    """

    # find all IPs
    return set(
        re.findall(
            r"""\b(?:
             (?:[\da-f]{1,4}(?::[\da-f]{0,4})+)(?:/[\d]+)?|
             (?:(?:\d{1,3}\.){3}\d{1,3}(?:/[\d\.]+)?)|
             (?:(?:\d{1,3}\.){0,3}\d{1,3}/[\d\.]+)
             )\b""",
            text,
            flags=re.IGNORECASE | re.VERBOSE,
        )
    )


def extract_urls(
    text: str, log: logging.Logger, examples: bool = False, common: bool = False
) -> set:
    """
    Return a list of URLs in a text string.

    @param      text      The text to extract URLs from
    @param      examples  Include example URLs
    @param      common    Include URLs that are common in IETF documents

    @return     List of URLs.
    """

    # find all URLs
    extractor = urlextract.URLExtract()
    extractor.update_when_older(7)  # update TLDs when older than 7 days
    text = unfold(text)
    urls = []
    for url in extractor.gen_urls(text):
        url = url.rstrip(".\"]'>;,")
        # if not re.search(r"://", url):
        #     url = "http://" + url
        if re.match(r"[\d\.:a-f]+", url, flags=re.IGNORECASE):
            # skip literal IP addresses
            continue
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
                r"example\.(com|net|org)|\.example",
                urllib.parse.urlparse(u).netloc
                if urllib.parse.urlparse(u).netloc
                else u,
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
                r"^(?:(\d\.?)+\s+)?(?:Non-Norm|Inform)ative\s+References?\s*$",
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

    refs = {}
    for part in parts:
        refs[part] = re.findall(
            r"(\[(?:\d+|[a-z]+(?:[-_.]?\w+)*)\]"
            + (r"|RFC\d+|draft-[-a-z\d_.]+" if part == "text" else r"")
            + r")",
            unfold(parts[part]),
            flags=re.IGNORECASE,
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


def get_relationships(
    doc: str,
) -> dict:
    """
    Extract the RFCs that are intended to be updated or obsoleted by this
    document.

    @param      doc   The document to extract the information from

    @return     A dict of relationships and lists of RFC *numbers*
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
            result[rel] = re.sub("rfc", "", result[rel], flags=re.IGNORECASE)
            result[rel] = re.sub(r"[,\s]+(\w)", r",\1", result[rel])
            result[rel] = result[rel].strip().split(",")
            result[rel] = [r for r in result[rel] if r]
    return result


def basename(item: str) -> str:
    """
    Return the base name of a given item by stripping the path, the version
    information and the txt suffix.

    @param      item  The item to return the base name for

    @return     The base name of the item
    """
    return re.sub(r"^(?:.*/)?(.*[^-]+)(-\d+)+(?:\.txt)?$", r"\1", item)



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
