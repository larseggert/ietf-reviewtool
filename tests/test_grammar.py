"""
Tests for ietf_reviewtool.grammar.

SPDX-License-Identifier: GPL-2.0
"""

import unittest

from ietf_reviewtool.grammar import line_starts
from ietf_reviewtool.util.text import unfold


class TestLineStarts(unittest.TestCase):
    """Tests for line_starts()."""

    def test_line_starts(self):
        """Each line maps to where its text starts in the unfolded text."""
        lines = [
            "1.  Introduction\n",
            "\n",
            "   A paragraph that wraps onto a\n",
            "   second line, with a hyphen-\n",
            "   ated word.\n",
            "\n",
            "   Another paragraph.\n",
        ]
        unfolded = unfold("".join(lines))
        starts = line_starts(lines, unfolded)
        self.assertEqual(len(starts), len(lines))
        for line, start in zip(lines, starts):
            if line.strip():
                with self.subTest(line=line):
                    self.assertTrue(unfolded[start:].startswith(line.strip()))
        # blank lines keep the preceding offset
        self.assertEqual(starts[1], starts[0])
        self.assertEqual(starts[5], starts[4])


if __name__ == "__main__":
    unittest.main()
