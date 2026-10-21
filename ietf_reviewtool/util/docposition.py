"""ietf-reviewtool document position module"""

import re
from collections import Counter

# pattern matching section headings
SECTION_PATTERN = re.compile(
    r"""^(?:[\- ]\s)?(Abstract|Status\sof\sThis\sMemo|Copyright\sNotice|
        Editorial\sNote|Table\sof\sContents|Acknowledge?ments?|Contributors?|
        (?:(?:Non-)Normative\s|Informative\s)?References?|
        Author(?:'?s?'?)?\sAddress(?:es)?|
        (?:Appendix\s+)?[\dA-Z]+(?:\.\d+)*\.?\s|
        \d+(?:\.\d+)*\.?)(.*)""",
    re.VERBOSE,
)

# pattern matching the marker that starts a list item
LIST_MARKER = re.compile(
    r"^(?:[*•]\s+|o\s{2,}|(?:\d+|[a-zA-Z]|[ivxIVX]+)\.\s{2,}|\(\w+\)\s{2,})(?=\S)"
)

# maximum line length of the plain-text rendering of RFCs and I-Ds
LINE_LENGTH = 72

# pattern matching a compact definition list entry
DEFINITION = re.compile(r"^[^\s:][^:]{0,60}:\s{2,}\S")

# pattern matching a figure or table caption
CAPTION = re.compile(r"^(?:Figure|Table)\s+\d+(?::|$)")

# pattern matching a line of ASCII art, a table or bracketed code
ART = re.compile(r"^[+|}]|{$")


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _centered(indent: int, body: str) -> bool:
    return abs(indent - (LINE_LENGTH - len(body)) // 2) <= 2


def body_indent(lines: list[str]) -> int:
    """
    Return the indentation of the body text of a document, i.e., the most common
    indentation of its non-blank lines.

    @param      lines  The lines of the document

    @return     The body text indentation.
    """
    indents = Counter(_indent(line) for line in lines if line.strip())
    return indents.most_common(1)[0][0] if indents else 0


class DocPosition:
    """
    Class to maintain the current position in a document.

    Paragraphs are numbered like the pilcrow anchors in the HTML rendering of a
    document (e.g., "#section-11-2"), i.e., by counting the top-level elements of a
    section. A list (with all its items and their sub-paragraphs), a figure (with its
    caption) or a table count as one element each. The paragraph number is zero
    between a section heading and its first element.

    Only lines of the original document are counted, so text added by a reviewer
    does not affect the numbering; such text is attributed to the paragraph it is
    in or follows.
    """

    para_num: int
    sec_title: str
    had_non_numbered_sec: bool

    def __init__(
        self,
        para_num: int = 0,
        sec_title: str = "",
        had_non_numbered_sec: bool = False,
        base_indent: int = 3,
    ):
        self.para_num = para_num
        self.sec_title = sec_title
        self.had_non_numbered_sec = had_non_numbered_sec
        # kind of the current top-level element: "p", "list", "fig", "closed" or None
        self.kind: str | None = None
        # indentation of top-level body text (see body_indent())
        self.base_indent = base_indent
        # indentation of the text of the current list's items
        self.list_indent = 0
        # the previous line of the original document
        self.prev_text = ""
        # whether the next non-blank line starts a new block of text
        self.block_start = True
        # whether the current line continues a section heading
        self.in_heading = False
        # whether the current line continues a figure or table caption
        self.in_caption = False

    def fmt_section_and_paragraph(self, level: str = "") -> str:
        """
        Return a formatted prefix line indicating the current section name, paragraph
        number, and level.

        @param      self   The DocPosition object
        @param      level  The issue level to indicate in the prefix line

        @return     A formatted prefix line.
        """
        if self.para_num == 0:
            line = self.sec_title or "Front matter"
        else:
            line = f"{self.sec_title}, p" if self.sec_title else "P"
            line += f"aragraph {self.para_num}"
        if level:
            line += f", {level}"
        return line + "\n"

    def update(self, nxt: str | None, cur: str, is_diff: bool = True) -> None:
        """
        Update the current paragraph number and section title, based on the next and
        current lines of text.

        @param      self     The DocPosition object
        @param      nxt      The next line in the diff
        @param      cur      The current line in the diff
        @param      is_diff  Indicates if difference

        @return     None
        """
        if is_diff:
            # only lines from the original document count
            if cur[0] not in " -":
                return
            text = cur[2:]
            nxt_text = nxt[2:] if nxt and nxt[0] in " -" else None
        else:
            text = cur
            nxt_text = nxt
            # make headings look like they do in a diff, so they must be flush-left
            cur = "  " + cur
            nxt = "  " + nxt if nxt is not None else None

        text = text.rstrip()
        if not text:
            self.block_start = True
            self.in_heading = False
            self.in_caption = False
            return

        if self.in_heading:
            # a wrapped section heading
            return

        # track sections
        pot_sec = SECTION_PATTERN.search(cur)
        if pot_sec and nxt and (re.search(r"^([\- ] +$|\+ )", nxt) or len(cur) > 65):
            pot_sec_title = pot_sec.group(1).strip()
            if re.match(r"\d", pot_sec_title):
                if self.had_non_numbered_sec:
                    self._new_section(
                        "Section " + re.sub(r"(.*)\.$", r"\1", pot_sec_title)
                    )
            else:
                self.had_non_numbered_sec = True
                self._new_section(f'"{pot_sec_title}"')
            return

        # track paragraphs
        indent = _indent(text)
        body = text.strip()
        if self.in_caption and indent > self.base_indent:
            # a wrapped caption
            pass
        elif CAPTION.match(body) and indent > self.base_indent:
            # a caption ends the figure or table it belongs to, unless that is
            # within a list item
            if self.kind is None:
                self._new_element("fig")
            if self.kind != "list":
                self.kind = "closed"
            self.in_caption = True
            self.block_start = True
        else:
            self.in_caption = False
            if self._starts_block_without_blank(indent, body):
                self.block_start = True
            if self.block_start:
                self._start_block(indent, body, nxt_text)
                self.block_start = False
        self.prev_text = text

    def _starts_block_without_blank(self, indent: int, body: str) -> bool:
        """
        Determine whether a line at body indentation that does not follow a blank
        line nevertheless starts a new block of text: the next item of a compact list,
        or text after a list or figure whose separating blank line was removed along
        with a page break.

        @param      self    The DocPosition object
        @param      indent  The indentation of the line
        @param      body    The line, without indentation

        @return     True if the line starts a new block of text.
        """
        if self.block_start or indent != self.base_indent or ART.match(body):
            return False
        prev_indent = _indent(self.prev_text)
        if self.kind == "list":
            if LIST_MARKER.match(body) or DEFINITION.match(body):
                return True
            # unless the previous line was the last one of a paragraph, i.e., the
            # first word of this line would have fit onto it, this line continues it
            word = body.split()[0]
            return len(self.prev_text) + 1 + len(word) <= LINE_LENGTH
        return self.kind == "fig" and prev_indent != indent

    def _new_section(self, title: str) -> None:
        self.sec_title = title
        self.para_num = 0
        self.kind = None
        self.block_start = True
        self.in_heading = True

    def _new_element(self, kind: str) -> None:
        self.para_num += 1
        self.kind = kind

    def _start_block(self, indent: int, body: str, nxt_text: str | None) -> None:
        """
        Determine whether a block of text continues the current top-level element or
        starts a new one.

        @param      self      The DocPosition object
        @param      indent    The indentation of the first line of the block
        @param      body      The first line of the block, without indentation
        @param      nxt_text  The line following it in the original document, if known
        """
        if indent != self.base_indent or ART.match(body):
            if self.kind == "list" and indent >= self.list_indent:
                if ART.match(body) and _centered(indent, body):
                    # a centered figure or table following a list, while those
                    # within a list item are aligned with its text
                    self._new_element("fig")
            elif self.kind != "fig":
                # artwork or an indented block following text: a figure, table, etc.
                self._new_element("fig")
            return

        marker = LIST_MARKER.match(body)
        nxt_indent = _indent(nxt_text) if nxt_text and nxt_text.strip() else None
        nxt_item = nxt_text is not None and bool(
            LIST_MARKER.match(nxt_text.strip()) or DEFINITION.match(nxt_text.strip())
        )
        if (marker or DEFINITION.match(body) or (nxt_indent or 0) > indent) and (
            # unless it is a paragraph that merely starts like an item
            nxt_indent != indent or nxt_item
        ):
            # a list item or a definition list entry
            if self.kind != "list":
                self._new_element("list")
            if marker:
                self.list_indent = indent + marker.end()
            elif nxt_indent is not None and nxt_indent > indent:
                self.list_indent = nxt_indent
            else:
                self.list_indent = indent + 3
            return

        self._new_element("p")
