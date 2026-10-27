"""
Tests for ietf_reviewtool.util.text.extract_urls.

SPDX-License-Identifier: GPL-2.0
"""

import logging
import unittest

from ietf_reviewtool.util.text import extract_urls, mask_section_references

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

    def test_oxford_comma_list_skipped(self):
        """All numbers in a list with a serial comma are skipped."""
        for conj in ("and", "or"):
            with self.subTest(conj=conj):
                text = (
                    "1.  Introduction\n"
                    "\n"
                    f"   See Sections 3.1.3.7, 4.1.3.7, {conj} 5.1.3.7 of [X].\n"
                )
                self.assertEqual(all_urls(text), set())

    def test_address_equal_to_reference_kept(self):
        """An address that equals a referenced section number is still found."""
        text = (
            "1.  Introduction\n"
            "\n"
            "   See Section 3.1.3.7 of [OtherSpec].  The resolver address is\n"
            "   3.1.3.7.\n"
        )
        self.assertEqual(all_urls(text), {"3.1.3.7"})

    def test_numeric_hostname_kept(self):
        """A hostname starting with a digit is not cut short after "Section"."""
        for text in ("See Section 3.1 or 3gpp.org.", "See Section 3gpp.org."):
            with self.subTest(text=text):
                self.assertEqual(
                    all_urls(f"1.  Introduction\n\n   {text}\n"), {"3gpp.org"}
                )

    def test_wrapped_url_ending_in_section_kept(self):
        """A URL ending in "#section" and a number wrapped onto the next line is
        reassembled before section references are masked."""
        text = (
            "1.  Introduction\n"
            "\n"
            "   See <https://www.ietf.org/spec.html#section\n"
            "   3.1.3.7>.\n"
        )
        self.assertEqual(
            all_urls(text), {"https://www.ietf.org/spec.html#section3.1.3.7"}
        )


class TestMaskSectionReferences(unittest.TestCase):
    """Tests for mask_section_references()."""

    def test_mask(self):
        """Only the numbers in section references are masked."""
        self.assertEqual(
            mask_section_references("Sections 6.1,\n   7.2, and 8 of RFC 9000."),
            "Sections    ,\n      , and   of RFC 9000.",
        )

    def test_numeric_hostname_not_masked(self):
        """A hostname starting with a digit is not part of a reference."""
        self.assertEqual(
            mask_section_references("Section 3.1 or 3gpp.org"),
            "Section     or 3gpp.org",
        )


if __name__ == "__main__":
    unittest.main()
