"""
Tests for ietf_reviewtool.util.text.extract_urls.

SPDX-License-Identifier: GPL-2.0
"""

import logging
import unittest

from ietf_reviewtool.util.text import extract_urls

log = logging.getLogger(__name__)


def all_urls(text: str) -> set[str]:
    """Return the URLs found in any part of a document."""
    return set().union(*extract_urls(text, log).values())


class TestExtractUrls(unittest.TestCase):
    """Tests for extract_urls()."""

    def test_external_section_reference_skipped(self):
        """A section number of another document is not mistaken for a URL."""
        text = (
            "1.  Introduction\n"
            "\n"
            "   For example, securing unsigned ID Tokens via transmission over\n"
            "   TLS in Section 3.1.3.7 and the use of unsigned request objects\n"
            "   in Sections 6.1.2.3 and 7.2.1.4 of [OpenID.Core].\n"
        )
        self.assertEqual(all_urls(text), set())

    def test_folded_section_reference_skipped(self):
        """A section number on the line after "Section" is not a URL."""
        text = (
            "1.  Introduction\n"
            "\n"
            "   This is described by the specification in its Section\n"
            "   3.1.3.7.\n"
        )
        self.assertEqual(all_urls(text), set())

    def test_url_kept(self):
        """A real URL is still found."""
        text = "1.  Introduction\n\n   See https://openid.net/specs/core.html.\n"
        self.assertEqual(all_urls(text), {"https://openid.net/specs/core.html"})

    def test_non_http_url_kept_next_to_section_reference(self):
        """A non-HTTP URL is still found when a section reference is skipped."""
        text = (
            "1.  Introduction\n"
            "\n"
            "   See Section 3.1.3.7 and ftp://ftp.rfc-editor.org/in-notes/x.txt.\n"
        )
        self.assertEqual(all_urls(text), {"ftp://ftp.rfc-editor.org/in-notes/x.txt"})


if __name__ == "__main__":
    unittest.main()
