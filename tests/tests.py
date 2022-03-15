"""
Tests for ietf-reviewtool.py.

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

import re
import unittest

import ietf_reviewtool.ietf_reviewtool as irt
from ietf_reviewtool.review import IetfReview


def munge(text: str, repl=r"word") -> str:
    """Replace "sentence" with repl."""
    return re.sub(r"sentence", repl, text)


class TestReviewItem(unittest.TestCase):
    """
    Tests for review_item().
    """

    maxDiff = None

    single_line = ["This is a single sentence.\n"]

    two_lines = ["This is a first sentence.\n", "This is a second sentence.\n"]

    four_lines = [
        "This is a first sentence.\n",
        "This is a second sentence.\n",
        "This is a third sentence.\n",
        "This is a fourth sentence.\n",
    ]

    def compute_and_verify_result(self, orig, review, expected_result):
        """Compute and verify the review results."""
        result = irt.review_item(orig, review, IetfReview())
        self.assertEqual(str(result), str(expected_result))

    def test_all_empty(self):
        """Empty document, empty review."""
        self.compute_and_verify_result("", "", IetfReview())

    def test_review_empty(self):
        """Dummy document, empty review."""
        self.compute_and_verify_result(self.single_line, self.single_line, IetfReview())

    def test_single_line_inline_nits(self):
        """Single line, only inline nits."""
        review = self.single_line.copy()
        review[0] = munge(review[0])
        expected = IetfReview() | {
            "nit": [
                "Paragraph 1, nit:\n",
                "- This is a single sentence.\n",
                "-                  ^^^^^^^^\n",
                "+ This is a single word.\n",
                "+                  ^^^^\n",
                "\n",
            ],
        }
        self.compute_and_verify_result(self.single_line, review, expected)

    def test_two_lines_inline_nits(self):
        """Two lines, only inline nits."""
        expected = [
            IetfReview()
            | {
                "nit": [
                    "Paragraph 1, nit:\n",
                    "- This is a first sentence.\n",
                    "-                 ^^^^^^^^\n",
                    "+ This is a first word.\n",
                    "+                 ^^^^\n",
                    "\n",
                ],
            },
            IetfReview()
            | {
                "nit": [
                    "Paragraph 1, nit:\n",
                    "- This is a second sentence.\n",
                    "-                  ^^^^^^^^\n",
                    "+ This is a second word.\n",
                    "+                  ^^^^\n",
                    "\n",
                ],
            },
        ]

        for pos, exp in enumerate(expected):
            review = self.two_lines.copy()
            review[pos] = munge(review[pos])
            with self.subTest(pos=pos):
                self.compute_and_verify_result(self.two_lines, review, exp)

    def test_two_lines_inline_discuss_single_line(self):
        """Two lines with an inline DISCUSS between them."""
        expected = [
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "A line of DISCUSS.\n",
                    "\n",
                ],
            },
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "A line of DISCUSS.\n",
                    "\n",
                    "Paragraph 1, discuss:\n",
                    "A line of DISCUSS.\n",
                    "\n",
                ],
            },
        ]

        for cnt, exp in enumerate(expected):
            review = self.two_lines.copy()
            for _ in range(cnt + 1):
                review.insert(1, "DISCUSS: A line of DISCUSS.\n")
            with self.subTest(cnt=cnt):
                self.compute_and_verify_result(self.two_lines, review, exp)

    def test_two_lines_discuss(self):
        """Two lines with a DISCUSS around one of them."""
        expected = [
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "> This is a first sentence.\n",
                    "> This is a second sentence.\n",
                    "\n",
                    "First line of DISCUSS.\n",
                    "Second line of DISCUSS.\n",
                    "\n",
                ],
            },
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "> This is a second sentence.\n",
                    "\n",
                    "First line of DISCUSS.\n",
                    "Second line of DISCUSS.\n",
                    "\n",
                ],
            },
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "First line of DISCUSS.\n",
                    "Second line of DISCUSS.\n",
                    "\n",
                ],
            },
        ]

        for pos, exp in enumerate(expected):
            review = self.two_lines.copy()
            review.insert(pos, "DISCUSS:\n")
            review.append("First line of DISCUSS.\n")
            review.append("Second line of DISCUSS.\n")

            with self.subTest(pos=pos):
                self.compute_and_verify_result(self.two_lines, review, exp)

    def test_two_lines_discuss_with_nits(self):
        """Two lines with a DISCUSS around one of them, and nits inside."""
        expected = [
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "> This is a first sentence.\n",
                    "> This is a second sentence.\n",
                    "\n",
                    "First line of DISCUSS.\n",
                    "Second line of DISCUSS.\n",
                    "\n",
                ],
                "nit": [
                    "Paragraph 1, nit:\n",
                    "- This is a first sentence.\n",
                    "-                 ^^^^^^^^\n",
                    "+ This is a first word.\n",
                    "+                 ^^^^\n",
                    "\n",
                ],
            },
            IetfReview()
            | {
                "discuss": [
                    "Paragraph 1, discuss:\n",
                    "> This is a first sentence.\n",
                    "> This is a second sentence.\n",
                    "\n",
                    "First line of DISCUSS.\n",
                    "Second line of DISCUSS.\n",
                    "\n",
                ],
                "nit": [
                    "Paragraph 1, nit:\n",
                    "- This is a first sentence.\n",
                    "-                 --------\n",
                    "+ This is a first .\n",
                    "\n",
                ],
            },
        ]
        repl = [r"word", r""]

        for pos, exp in enumerate(expected):
            review = self.two_lines.copy()
            review[0] = munge(review[0], repl[pos])
            review.insert(0, "DISCUSS:\n")
            review.append("First line of DISCUSS.\n")
            review.append("Second line of DISCUSS.\n")

            with self.subTest(pos=pos):
                self.compute_and_verify_result(self.two_lines, review, exp)


if __name__ == "__main__":
    unittest.main()
