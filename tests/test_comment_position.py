"""
Tests for the paragraph numbers of review comments.

SPDX-License-Identifier: GPL-2.0
"""

import unittest
from types import SimpleNamespace

from ietf_reviewtool.review import IetfReview
from ietf_reviewtool.util.docposition import DocPosition


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


class TestCommentPosition(unittest.TestCase):
    """Tests for the paragraph numbers of review comments."""

    def test_comment_after_blank_line(self):
        """A comment after the blank line ending a paragraph refers to it."""
        # the original blank line before the comment (difflib may also align it
        # after the comment)
        diff = [
            "  Abstract\n",
            "  \n",
            "     The abstract.\n",
            "  \n",
            "  1.  Introduction\n",
            "  \n",
            "     First paragraph.\n",
            "  \n",
            "     Second paragraph.\n",
            "  \n",
            "+ COMMENT: About the second paragraph.\n",
            "+ More about it.\n",
            "     Third paragraph.\n",
        ]
        self.assertEqual(comment_headings(diff), ["Section 1, paragraph 2"])

    def test_comment_after_heading(self):
        """A comment between a heading and the first paragraph names the section."""
        diff = [
            "  Abstract\n",
            "  \n",
            "     The abstract.\n",
            "  \n",
            "  1.  Introduction\n",
            "  \n",
            "+ COMMENT: About the section.\n",
            "     First paragraph.\n",
        ]
        self.assertEqual(comment_headings(diff), ["Section 1"])

    def test_no_paragraph_zero(self):
        """Without a paragraph, only the section is named."""
        pos = DocPosition(sec_title="Section 1")
        self.assertEqual(pos.fmt_section_and_paragraph(), "Section 1\n")
        pos.para_num = 2
        self.assertEqual(pos.fmt_section_and_paragraph(), "Section 1, paragraph 2\n")


if __name__ == "__main__":
    unittest.main()
