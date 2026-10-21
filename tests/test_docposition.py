"""
Tests for paragraph numbering in ietf_reviewtool.util.docposition.

Paragraph numbers are expected to match the pilcrow anchors of the HTML rendering
of a document, e.g., "#section-2-3" is Section 2, paragraph 3.

SPDX-License-Identifier: GPL-2.0
"""

import unittest
from types import SimpleNamespace

from ietf_reviewtool.review import IetfReview
from ietf_reviewtool.util.docposition import DocPosition, body_indent

DOC = """\
Abstract

   This is the abstract.

1.  Introduction

   First paragraph of the introduction, which is long enough to wrap
   onto a second line.

   Second paragraph.

   Third paragraph introduces a list:

   *  First item of the list, which is long enough to wrap onto a
      second line.

      A sub-paragraph of the first item.

   *  Second item.

   Fourth paragraph, after the list.

   Value:  1
   Status:  permanent

   Fifth paragraph, after a definition list.

     +-----+     +-----+
     |  A  |---->|  B  |
     +-----+     +-----+

                     Figure 1: A figure caption that is long enough
                                    to wrap

   Sixth paragraph, after a figure.

2.  Second Section

   Only paragraph, with a heading that is long enough to wrap

"""

LINES = DOC.splitlines(keepends=True)


def positions(lines: list[str]) -> dict[str, tuple[str, int]]:
    """Return the position after each non-blank line, keyed by its text."""
    pos = DocPosition(base_indent=body_indent(lines))
    result = {}
    for num, cur in enumerate(lines):
        nxt = lines[num + 1] if num < len(lines) - 1 else None
        if nxt is not None:
            pos.update(nxt, cur, is_diff=False)
        if cur.strip():
            result[cur.strip()] = (pos.sec_title, pos.para_num)
    return result


def review(orig: list[str], current: list[str]) -> dict:
    """Return the comments of a review of current against orig."""
    doc = SimpleNamespace(
        name="draft-test", revision="00", orig_lines=orig, current_lines=current
    )
    rev = IetfReview(doc, gen_mkd=False, role="", gh_id="@test")  # type: ignore
    return rev._IetfReview__data  # type: ignore


def headings(data: dict, kind: str) -> list[str]:
    """Return the headings of the items of the given kind."""
    return [item.split("\n")[0] for items in data[kind].values() for item in items]


class TestDocPosition(unittest.TestCase):
    """Tests for DocPosition."""

    def test_body_indent(self):
        """The body indentation is the most common one."""
        self.assertEqual(body_indent(LINES), 3)
        self.assertEqual(body_indent(["a\n", "b\n", "  c\n"]), 0)
        self.assertEqual(body_indent([]), 0)

    def test_elements(self):
        """Lists, definition lists and figures count as one paragraph."""
        pos = positions(LINES)
        sec1 = "Section 1"
        expected = {
            "This is the abstract.": ('"Abstract"', 1),
            "onto a second line.": (sec1, 1),
            "Second paragraph.": (sec1, 2),
            "Third paragraph introduces a list:": (sec1, 3),
            "second line.": (sec1, 4),
            "A sub-paragraph of the first item.": (sec1, 4),
            "*  Second item.": (sec1, 4),
            "Fourth paragraph, after the list.": (sec1, 5),
            "Status:  permanent": (sec1, 6),
            "Fifth paragraph, after a definition list.": (sec1, 7),
            "|  A  |---->|  B  |": (sec1, 8),
            "to wrap": (sec1, 8),
            "Sixth paragraph, after a figure.": (sec1, 9),
            "Only paragraph, with a heading that is long enough to wrap": (
                "Section 2",
                1,
            ),
        }
        for line, exp in expected.items():
            with self.subTest(line=line):
                self.assertEqual(pos[line], exp)

    def test_artwork_in_list(self):
        """Artwork within a list item belongs to the list."""
        lines = [
            "Abstract\n",
            "\n",
            "   The abstract.\n",
            "\n",
            "1.  Introduction\n",
            "\n",
            "   *  First item, with a diagram:\n",
            "\n",
            "      +---+     +---+\n",
            "      | A |---->| B |\n",
            "      +---+     +---+\n",
            "\n",
            "   *  Second item.\n",
            "\n",
            "   Paragraph after the list.\n",
            "\n",
        ]
        pos = positions(lines)
        self.assertEqual(pos["| A |---->| B |"], ("Section 1", 1))
        self.assertEqual(pos["Paragraph after the list."], ("Section 1", 2))

    def test_figure_after_list(self):
        """A centered figure following a list is a separate element."""
        lines = [
            "Abstract\n",
            "\n",
            "   The abstract.\n",
            "\n",
            "1.  Introduction\n",
            "\n",
            "   *  First item.\n",
            "\n",
            "   *  Second item.\n",
            "\n",
            "                          +---+     +---+\n",
            "                          | A |---->| B |\n",
            "                          +---+     +---+\n",
            "\n",
            "   Paragraph after the figure.\n",
            "\n",
        ]
        pos = positions(lines)
        self.assertEqual(pos["| A |---->| B |"], ("Section 1", 2))
        self.assertEqual(pos["Paragraph after the figure."], ("Section 1", 3))


class TestCommentPosition(unittest.TestCase):
    """Tests for the paragraph numbers of review comments."""

    def insert(self, after: str, comment: list[str]) -> list[str]:
        """Return a copy of LINES with comment inserted after the given line."""
        idx = next(i for i, line in enumerate(LINES) if line.strip() == after)
        return LINES[: idx + 1] + comment + LINES[idx + 1 :]

    def test_comment_after_paragraph(self):
        """A comment between paragraphs refers to the preceding one."""
        for comment in (
            ["\n", "COMMENT: About the second paragraph.\n"],
            ["COMMENT: About the second paragraph.\n", "\n"],
        ):
            with self.subTest(comment=comment):
                current = self.insert("Second paragraph.", comment)
                self.assertEqual(
                    headings(review(LINES, current), "comment"),
                    ["Section 1, paragraph 2"],
                )

    def test_comment_in_paragraph(self):
        """A comment inside a paragraph refers to it."""
        current = self.insert(
            "First paragraph of the introduction, which is long enough to wrap",
            ["COMMENT: About the first paragraph.\n"],
        )
        self.assertEqual(
            headings(review(LINES, current), "comment"),
            ["Section 1, paragraph 1"],
        )

    def test_comment_after_term(self):
        """A comment after a definition list term does not change the numbering."""
        orig = [
            "Abstract\n",
            "\n",
            "   The abstract.\n",
            "\n",
            "1.  Introduction\n",
            "\n",
            "   First term\n",
            "      Its definition.\n",
            "\n",
            "   Second term\n",
            "      Its definition.\n",
            "\n",
            "   Paragraph after the list.\n",
            "\n",
        ]
        current = list(orig)
        current.insert(7, "COMMENT: About the first term.\n")
        current.append("COMMENT: About the paragraph.\n")
        self.assertEqual(
            headings(review(orig, current), "comment"),
            ["Section 1, paragraph 1", "Section 1, paragraph 2"],
        )

    def test_comment_in_list(self):
        """A comment inside a list refers to the list."""
        current = self.insert("*  Second item.", ["COMMENT: About the list.\n"])
        self.assertEqual(
            headings(review(LINES, current), "comment"),
            ["Section 1, paragraph 4"],
        )


if __name__ == "__main__":
    unittest.main()
