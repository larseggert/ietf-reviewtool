"""
Tests for ietf_reviewtool.util.format.

SPDX-License-Identifier: GPL-2.0
"""

import unittest
from types import SimpleNamespace

from ietf_reviewtool.review import IetfReview


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


class TestFmtComment(unittest.TestCase):
    """Tests for fmt_comment()."""

    def test_comment_with_context(self):
        """A comment quoting context does not shift later paragraph numbers."""
        diff = [
            "  Abstract\n",
            "  \n",
            "     The abstract.\n",
            "  \n",
            "  1.  Introduction\n",
            "  \n",
            "+ COMMENT:\n",
            "     First paragraph.\n",
            "+ About the first paragraph.\n",
            "  \n",
            "     Second paragraph.\n",
            "+ COMMENT: About the second paragraph.\n",
            "  \n",
            "     Third paragraph.\n",
        ]
        self.assertEqual(
            comment_headings(diff),
            ["Section 1, paragraph 1", "Section 1, paragraph 2"],
        )


if __name__ == "__main__":
    unittest.main()
