"""
Tests for ietf_reviewtool.review.strip_nits_from_diff.

SPDX-License-Identifier: GPL-2.0
"""

import unittest
from types import SimpleNamespace

from ietf_reviewtool.review import IetfReview, strip_nits_from_diff


def comment_headings(diff: list[str]) -> list[str]:
    """Return the headings of the comments gathered from a nit-free diff."""
    orig = [line[2:] for line in diff if line[0] in " -"]
    rev = IetfReview(
        SimpleNamespace(orig_lines=orig, current_lines=orig),  # type: ignore
        gen_mkd=False,
        role="",
        gh_id="@test",
    )
    rev.gather_comments(diff)
    data = rev._IetfReview__data  # type: ignore # pylint: disable=protected-access
    return [item.split("\n")[0] for items in data["comment"].values() for item in items]


class TestStripNits(unittest.TestCase):
    """Tests for strip_nits_from_diff()."""

    def test_deleted_blank_line_kept(self):
        """A deleted blank line of the original is kept as context."""
        diff = ["  First.\n", "- \n", "+ \n", "  Second.\n"]
        self.assertEqual(
            strip_nits_from_diff(diff), ["  First.\n", "  \n", "  Second.\n"]
        )

    def test_deleted_blank_line_separates_paragraphs(self):
        """A deleted blank line still separates two paragraphs of the original."""
        diff = [
            "  Abstract\n",
            "  \n",
            "     The abstract.\n",
            "  \n",
            "  1.  Introduction\n",
            "  \n",
            "     First paragraph.\n",
            "- \n",
            "     Second paragraph.\n",
            "+ COMMENT: About the second paragraph.\n",
            "  \n",
            "     Third paragraph.\n",
        ]
        self.assertEqual(
            comment_headings(strip_nits_from_diff(diff)), ["Section 1, paragraph 2"]
        )

    def test_nit_before_deleted_blank_line(self):
        """A nit followed by a deleted blank line refers to its own paragraph."""
        orig = [
            "Abstract\n",
            "\n",
            "   The abstract.\n",
            "\n",
            "1.  Introduction\n",
            "\n",
            "   First paragraf.\n",
            "\n",
            "   Second paragraph.\n",
        ]
        current = orig[:6] + ["   First paragraph.\n"] + orig[8:]
        rev = IetfReview(
            SimpleNamespace(orig_lines=orig, current_lines=current),  # type: ignore
            gen_mkd=False,
            role="",
            gh_id="@test",
        )
        data = rev._IetfReview__data  # type: ignore # pylint: disable=protected-access
        self.assertEqual(
            [item.split("\n")[0] for items in data["nit"].values() for item in items],
            ["Section 1, paragraph 1"],
        )


if __name__ == "__main__":
    unittest.main()
