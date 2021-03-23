"""
Tests for ietf-reviewtool.py.
"""

import importlib
import re
import unittest
import pprint

irt = importlib.import_module("ietf-reviewtool")


class TestReviewItem(unittest.TestCase):
    """
    Tests for review_item().
    """

    empty_review = {"discuss": [], "comment": [], "nit": []}

    single_line = ["This is a single sentence.\n"]

    two_lines = ["This is a first sentence.\n", "This is a second sentence.\n"]

    def compute_and_verify_result(self, orig, review, expected_result):
        """Compute and verify the review results."""
        result = irt.review_item(orig, review)
        # print(result)
        # print(irt.fmt_review(result))
        self.assertEqual(result, expected_result)

    def test_all_empty(self):
        """Empty document, empty review."""
        self.compute_and_verify_result("", "", self.empty_review)

    def test_review_empty(self):
        """Dummy document, empty review."""
        self.compute_and_verify_result(self.single_line, "", self.empty_review)

    def test_single_line_inline_nits(self):
        """Single line, only inline nits."""
        review = self.single_line.copy()
        review[0] = re.sub(r"sentence", r"word", review[0])
        expected = self.empty_review | {
            "nit": [
                "Paragraph 1, nit:\n",
                "- This is a single sentence.\n",
                "                   ^^^^^^^^\n",
                "+ This is a single word.\n",
                "                   ^^^^\n",
                "\n",
            ],
        }
        self.compute_and_verify_result(self.single_line, review, expected)

    def test_two_lines_inline_nits(self):
        """Two lines, only inline nits."""
        review = self.two_lines.copy()
        review[0] = re.sub(r"sentence", r"word", review[0])
        expected = self.empty_review | {
            "nit": [
                "Paragraph 0, nit:\n",
                "- This is a first sentence.\n",
                "                  ^^^^^^^^\n",
                "+ This is a first word.\n",
                "                  ^^^^\n",
                "\n",
            ],
        }
        self.compute_and_verify_result(self.two_lines, review, expected)

    def test_two_lines_inline_discuss_single_line(self):
        """Two lines with an inline single-line DISCUSS between them."""
        review = self.two_lines.copy()
        review.insert(1, "DISCUSS: A single-line inline DISCUSS.\n")
        expected = self.empty_review | {
            "discuss": [
                "Paragraph 0, discuss:\n",
                "> This is a second sentence.\n",
                "\n",
                "A single-line inline DISCUSS.\n",
                "\n",
            ],
        }
        self.compute_and_verify_result(self.two_lines, review, expected)

    def test_two_lines_inline_discuss_two_lines(self):
        """Two lines with an inline two-line DISCUSS between them."""
        review = self.two_lines.copy()
        review.insert(1, "DISCUSS: A two-line inline DISCUSS.\n")
        review.insert(2, "Second line of DISCUSS.\n")
        expected = self.empty_review | {
            "discuss": [
                "Paragraph 0, discuss:\n",
                "> This is a second sentence.\n",
                "\n",
                "A two-line inline DISCUSS.\n",
                "Second line of DISCUSS.\n",
                "\n",
            ],
        }
        self.compute_and_verify_result(self.two_lines, review, expected)


if __name__ == "__main__":
    unittest.main()
