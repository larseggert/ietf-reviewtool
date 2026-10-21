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

import logging
import re
import unittest
from unittest import mock

import httpx

import ietf_reviewtool.ietf_reviewtool as irt
from ietf_reviewtool.review import IetfReview
from ietf_reviewtool.util import fetch


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


class TestCheckUrls(unittest.TestCase):
    """
    Tests for check_urls().
    """

    def test_reachability_checks_bypass_cache(self):
        fetch = mock.AsyncMock(return_value="")
        urls = {"part": {"https://example.org/", "http://example.com/"}}
        with (
            mock.patch.object(irt, "extract_urls", return_value=urls),
            mock.patch.object(irt, "fetch_url_async", fetch),
        ):
            irt.check_urls(mock.MagicMock(), mock.MagicMock())

        self.assertEqual(fetch.call_count, 3)
        for call in fetch.call_args_list:
            self.assertIs(call.kwargs["use_cache"], False)
            self.assertEqual(call.kwargs["method"], "HEAD")


class TestFetchUrl(unittest.TestCase):
    """
    Tests for fetch_url().
    """

    def setUp(self):
        self.requests = []
        self.saved_client = fetch._client

    def tearDown(self):
        fetch._client = self.saved_client

    def use_handler(self, handler):
        """Install a mock transport that records requests."""

        def record(request):
            self.requests.append(request)
            return handler(request)

        fetch._client = httpx.AsyncClient(transport=httpx.MockTransport(record))

    def test_head_timeout_falls_back_to_get(self):
        def handler(request):
            if request.method == "HEAD":
                raise httpx.ReadTimeout("timed out", request=request)
            return httpx.Response(206, text="partial")

        self.use_handler(handler)
        result = fetch.fetch_url(
            "https://example.org/", logging.getLogger(), False, "HEAD"
        )
        self.assertIsNotNone(result)
        self.assertEqual([r.method for r in self.requests], ["HEAD", "GET"])
        self.assertEqual(self.requests[1].headers["Range"], "bytes=0-100")
        self.assertEqual(self.requests[0].extensions["timeout"]["read"], 10.0)
        self.assertEqual(self.requests[1].extensions["timeout"]["read"], 30.0)

    def test_head_connect_error_does_not_retry(self):
        def handler(request):
            raise httpx.ConnectError("unreachable", request=request)

        self.use_handler(handler)
        result = fetch.fetch_url(
            "https://example.org/", logging.getLogger(), False, "HEAD"
        )
        self.assertIsNone(result)
        self.assertEqual([r.method for r in self.requests], ["HEAD"])


if __name__ == "__main__":
    unittest.main()
