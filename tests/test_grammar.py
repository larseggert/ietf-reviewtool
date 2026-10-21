"""
Tests for ietf_reviewtool.grammar.

SPDX-License-Identifier: GPL-2.0
"""

import unittest

from ietf_reviewtool.grammar import advance_to, line_starts
from ietf_reviewtool.util.docposition import DocPosition
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
        # blank lines start just past the text of the preceding line
        for blank in (1, 5):
            self.assertEqual(
                starts[blank], starts[blank - 1] + len(lines[blank - 1].strip())
            )

    def test_repeated_text(self):
        """Repeated text maps to its next occurrence, not to an earlier one."""
        lines = [
            "   Same paragraph.\n",
            "\n",
            "   Same paragraph.\n",
            "   paragraph.\n",
        ]
        unfolded = unfold("".join(lines))
        starts = line_starts(lines, unfolded)
        self.assertEqual(starts[0], 0)
        self.assertGreater(starts[2], starts[1])
        self.assertGreater(starts[3], starts[2])
        for num in (0, 2, 3):
            with self.subTest(num=num):
                self.assertTrue(unfolded[starts[num] :].startswith(lines[num].strip()))


class TestAdvanceTo(unittest.TestCase):
    """Tests for advance_to()."""

    lines = [
        "Abstract\n",
        "\n",
        "   The abstract.\n",
        "\n",
        "1.  Introduction\n",
        "\n",
        "   Alpha one.\n",
        "\n",
        "   Beta one, which is long enough to wrap onto\n",
        "   a second line, beta two.\n",
        "\n",
        "   Gamma one.\n",
    ]

    def test_positions(self):
        """Offsets in the first and last line of a paragraph map to it."""
        unfolded = unfold("".join(self.lines))
        starts = line_starts(self.lines, unfolded)
        expected = {
            "Alpha one": "Section 1, paragraph 1",
            "one.": "Section 1, paragraph 1",
            "Beta one": "Section 1, paragraph 2",
            "beta two": "Section 1, paragraph 2",
            "Gamma one": "Section 1, paragraph 3",
        }
        doc_pos = DocPosition()
        cur = 0
        for word, heading in expected.items():
            offset = unfolded.index(word, starts[cur - 1] if cur else 0)
            cur = advance_to(doc_pos, self.lines, starts, cur, offset)
            with self.subTest(word=word):
                self.assertEqual(doc_pos.fmt_section_and_paragraph(), heading + "\n")


if __name__ == "__main__":
    unittest.main()
