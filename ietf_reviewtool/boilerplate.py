"""ietf-reviewtool boilerplate module"""

import re

from .doc import Doc
from .review import IetfReview
from .util.text import normalize_ws, unfold, word_join


def check_tlp(doc: Doc, review: IetfReview) -> None:
    """
    Check the boilerplate against the Trust Legal Provisions (TLP).

    @param      doc     The document
    @param      review  The IETF Review document to add comments to

    @return     { description_of_the_return_value }
    """
    text = unfold(doc.orig)
    if re.search(TLP_6CI_PATTERN, text):
        msg = (
            "Document has an IETF Trust Provisions (TLP) Section 6.c(i) "
            "Publication Limitation clause. This means it can in most cases "
            "not be a WG document."
        )
        if doc.status.lower() == "standards track":
            msg += " And it cannot be published on the Standards Track."
        review.discuss("Boilerplate", msg)

    if re.search(r"Simplified\s+BSD\s+License", text, flags=re.IGNORECASE):
        review.nit(
            "Boilerplate",
            'Document still refers to the "Simplified BSD License", which '
            "was corrected in the TLP on September 21, 2021. It should "
            'instead refer to the "Revised BSD License".',
        )


def check_boilerplate(doc: Doc, review: IetfReview) -> None:
    """
    Check the RFC2119/RFC8174 boilerplate in the document.

    @param      doc     The document
    @param      review  The IETF Review document to add comments to

    @return     { description_of_the_return_value }
    """
    has_8174_boilerplate = set(re.findall(BOILERPLATE_8174_PATTERN, doc.orig))
    has_2119_boilerplate = set(re.findall(BOILERPLATE_2119_PATTERN, doc.orig))
    has_boilerplate_begin = set(re.findall(BOILERPLATE_BEGIN_PATTERN, doc.orig))

    doc_minus_boilerplate = re.sub(BOILERPLATE_8174_PATTERN, "", doc.orig)
    doc_minus_boilerplate = re.sub(BOILERPLATE_2119_PATTERN, "", doc_minus_boilerplate)
    doc_minus_boilerplate = re.sub(BOILERPLATE_2119_PATTERN, "", doc_minus_boilerplate)
    uses_keywords = set(re.findall(KEYWORDS_PATTERN, doc_minus_boilerplate))

    msg = None
    if uses_keywords:
        used_keywords = []
        for word in set(uses_keywords):
            used_keywords.append(normalize_ws(word))
        used_keywords_str = word_join(used_keywords, prefix='"', suffix='"')
        kw_text = f"keyword{'s' if len(uses_keywords) > 1 else ''}"

        if doc.status.lower() == "unknown":
            review.comment(
                "Boilerplate",
                "Document boilerplate does not seem to indicate the intended "
                "RFC status.",
            )
        elif doc.status.lower() in ["informational", "experimental"]:
            review.comment(
                "Boilerplate",
                f"Document has {doc.status} status, but uses the RFC2119 "
                f"{kw_text} {used_keywords_str}. Check if this is really "
                f"necessary?",
            )

        if not has_8174_boilerplate:
            msg = (
                f"This document uses the RFC2119 {kw_text} {used_keywords_str}, "
                f"but does not contain the recommended RFC8174 boilerplate."
            )
            if has_2119_boilerplate:
                msg += " (It contains a variant of the RFC2119 boilerplate.)"
            elif has_boilerplate_begin:
                msg += " (It contains some text with a similar beginning.)"
    else:
        if has_8174_boilerplate or has_2119_boilerplate or has_boilerplate_begin:
            msg = "This document does not use RFC2119 keywords, but contains "
            if has_8174_boilerplate:
                msg += "the RFC8174 boilerplate."
            elif has_2119_boilerplate:
                msg += "the RFC2119 boilerplate."
            elif has_boilerplate_begin:
                msg += "text with a beginning similar to the RFC2119 boilerplate."

    if msg:
        review.comment("Boilerplate", msg)

    if uses_keywords:
        lc_not = set(re.findall(LC_NOT_KEYWORDS_PATTERN, doc.orig))
        if lc_not:
            lc_not_str = word_join(list(lc_not), prefix='"', suffix='"')
            review.comment(
                "RFC2119 style",
                f'Using lowercase "not" together with an uppercase '
                f"RFC2119 keyword is not acceptable usage. Found: "
                f"{lc_not_str}",
            )

    sotm = ""
    for line in doc.orig_lines:
        if re.match(r"^\s+$", line):
            continue
        if len(sotm) == 0:
            if re.match(
                r"^\s*Status\s+of\s+This\s+Memo\s*$", line, flags=re.IGNORECASE
            ):
                sotm += " "
            continue
        if re.match(r"^\s*Copyright Notice\s*$", line):
            continue
        if re.match(r"^\s*Table\s+of\s+Contents\s*$", line, flags=re.IGNORECASE):
            break
        sotm += line
    sotm = unfold(sotm)

    if re.search(TLP_6A_PATTERN, sotm):
        sotm = re.sub(TLP_6A_PATTERN, r"", sotm)
    else:
        review.comment(
            "Boilerplate",
            'TLP Section 6.a "Submission Compliance for '
            'Internet-Drafts" boilerplate text seems to have issues.',
        )

    idg_issues = False

    for required, pat in ID_GUIDELINES_PATTERNS:
        if re.search(pat, sotm):
            sotm = re.sub(pat, r"", sotm)
        elif required:
            idg_issues = True
    if idg_issues and not re.search(COPYRIGHT_ALT_STREAMS, sotm):
        review.comment(
            "Boilerplate",
            "I-D Guidelines boilerplate text seems to have issues.",
        )

    if re.search(COPYRIGHT_IETF, sotm):
        sotm = re.sub(COPYRIGHT_IETF, r"", sotm)
    elif re.search(COPYRIGHT_ALT_STREAMS, sotm):
        sotm = re.sub(COPYRIGHT_ALT_STREAMS, r"", sotm)
        review.comment(
            "Boilerplate",
            'Document contains a TLP Section 6.b.ii "alternate streams" '
            "boilerplate.",
        )
    else:
        review.comment(
            "Boilerplate",
            'TLP Section 6.b "Copyright and License Notice" boilerplate '
            "text seems to have issues.",
        )

    if re.search(NO_MOD_RFC, sotm):
        sotm = re.sub(NO_MOD_RFC, r"", sotm)
        review.comment(
            "Boilerplate",
            "Document limits derivative works and/or RFC publication with "
            "a TLP Section 6.c.i boilerplate.",
        )
    elif re.search(NO_MOD_NO_RFC, sotm):
        sotm = re.sub(NO_MOD_NO_RFC, r"", sotm)
        review.comment(
            "Boilerplate",
            "Document limits derivative works and/or RFC publication with "
            "a TLP Section 6.c.ii boilerplate.",
        )
    elif re.search(PRE_5378, sotm):
        sotm = re.sub(PRE_5378, r"", sotm)
        review.comment(
            "Boilerplate",
            'Document has a TLP Section 6.c.iii "pre-5378" boilerplate. '
            "Is this really needed?",
        )

    if sotm and not re.match(TLP_6CI_PATTERN, sotm.strip()):
        review.nit(
            "Boilerplate",
            f'Found stray text in boilerplate: "{sotm.strip()}"',
        )


# pattern matching RFC2119 keywords
KEYWORDS_PATTERN = re.compile(
    r"""\W(MUST(?:\s+NOT)?|REQUIRED|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|
        (?:NOT\s+)?RECOMMENDED|MAY|OPTIONAL)\W""",
    re.VERBOSE,
)

# pattern matching RFC2119 keywords used with lowercase "not"
LC_NOT_KEYWORDS_PATTERN = re.compile(
    r"""\W((?:MUST|SHALL|SHOULD)\s+not|not\s+RECOMMENDED)\W""",
    re.VERBOSE,
)


# pattern matching variants of the RFC8174 boilerplate text
BOILERPLATE_8174_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+
        "SHALL",\s+"SHALL\s+NOT",\s+"SHOULD",\s+"SHOULD\s+NOT",\s+
        "RECOMMENDED",\s+"NOT\s+RECOMMENDED",\s+"MAY",\s+and\s+
        "OPTIONAL"\s+in\s+this\s+document\s+are\s+to\s+be\s+interpreted\s+
        as\s+described\s+in\s+\[?BCP\s*14\]?,?\s*\[?RFC\s*2119\]?,?\s*
        (?:and\s+)?\[?RFC\s*8174\]?,?\s+when,\s+and\s+only\s+when,\s+
        they\s+appear\s+in\s+all\s+capitals,\s+as\s+shown\s+
        (?:above|here)\.""",
    re.VERBOSE | re.MULTILINE,
)

# pattern matching variants of the RFC2119 boilerplate text
BOILERPLATE_2119_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+
        "SHALL",\s+"SHALL\s+NOT",\s+"SHOULD",\s+"SHOULD\s+NOT",\s+
        "RECOMMENDED",\s+(?:"NOT\s+RECOMMENDED",\s+)?"MAY",\s+and\s+
        "OPTIONAL"\s+in\s+this\s+document\s+are\s+to\s+be\s+interpreted\s+
        as\s+described\s+in\s+\[?RFC\s*2119\]?\.""",
    re.VERBOSE | re.MULTILINE,
)

# pattern matching the beginning of the RFC2119/RFC8174 boilerplate text
BOILERPLATE_BEGIN_PATTERN = re.compile(
    r"""The\s+key\s*words\s+"MUST",\s+"MUST\s+NOT",\s+"REQUIRED",\s+""",
)


TLP_6A_PATTERN = re.compile(
    r"""\s*This\s+Internet-Draft\s+is\s+submitted\s+in\s+full\s+conformance\s+
        with\s+the\s+provisions\s+of\s+BCP\s*78\s+and\s+BCP\s*79\.\s+""",
    re.VERBOSE,
)

TLP_6CI_PATTERN = re.compile(
    r"""This\s+document\s+may\s+not\s+be\s+modified,?\s+and\s+derivative\s+
            works\s+of\s+it\s+may\s+not\s+be\s+created""",
    re.VERBOSE,
)

ID_GUIDELINES_PATTERNS = [
    (
        True,
        re.compile(
            # this has an option for the pre-2010 text in it
            r"""Internet-Drafts\s+are\s+working\s+documents\s+of\s+the\s+
            Internet\s+Engineering\s+Task\s+Force\s+\(IETF\)
            (,\s+its\s+areas,\s+and\s+its\s+working\s+groups)?\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""Note\s+that\s+other\s+groups\s+may\s+also\s+distribute\s+
            working\s+documents\s+as\s+Internet-Drafts\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""The\s+list\s+of\s+current\s+Internet-Drafts\s+is\s+at\s+
            https?://datatracker\.ietf\.org/drafts/current/?\.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""Internet-Drafts\s+are\s+draft\s+documents\s+valid\s+for\s+a\s+
            maximum\s+of\s+six\s+months\s+and\s+may\s+be\s+updated,\s+
            replaced,\s+or\s+obsoleted\s+by\s+other\s+documents\s+at\s+any\s+
            time.\s+""",
            re.VERBOSE,
        ),
    ),
    (
        True,
        re.compile(
            r"""It\s+is\s+inappropriate\s+to\s+use\s+Internet-Drafts\s+as\s+
            reference\s+material\s+or\s+to\s+cite\s+them\s+other\s+than\s+as\s+
            \"work\s+in\s+progress(\.\"|\"\.)\s+""",
            re.VERBOSE,
        ),
    ),
    # this are not part of the boilerplate, but xml2rfc adds it?
    (
        False,
        re.compile(
            r"""This\s+Internet-Draft\s+will\s+expire\s+on\s+
            (\d{1,2}\s+[A-Za-z]+\s+\d{4}|[A-Za-z]+\s+\d{1,2},\s+\d{4})\.\s+""",
            re.VERBOSE,
        ),
    ),
    # this is pre-2010 text:
    (
        False,
        re.compile(
            r"""The\s+list\s+of\s+current\s+Internet-Drafts\s+can\s+be\s+
            accessed\s+at\s+https?://www\.ietf\.org/(?:ietf/)?1id-abstracts\.
            (?:html|txt)\.?\s*""",
            re.VERBOSE,
        ),
    ),
    (
        False,
        re.compile(
            r"""The\s+list\s+of\s+Internet-Draft\s+Shadow\s+Directories\s+can\s+
            be\s+accessed\s+at\s+https?://www\.ietf\.org/shadow\.html\.?\s*""",
            re.VERBOSE,
        ),
    ),
]

COPYRIGHT_ALT_STREAMS_PART = r"""Copyright\s+\(c\)\s+20\d{2}\s+IETF\s+Trust\s+
        and\s+the\s+persons\s+identified\s+as\s+the\s+document\s+authors\.\s+
        All\s+rights\s+reserved\.\s+
        This\s+document\s+is\s+subject\s+to\s+BCP\s*78\s+and\s+the\s+IETF\s+
        Trust's\s+Legal\s+Provisions\s+Relating\s+to\s+IETF\s+Documents\s+
        \(https?://trustee\.ietf\.org/license-info\)\s+in\s+effect\s+on\s+
        the\s+date\s+of\s+publication\s+of\s+this\s+document\.\s+
        Please\s+review\s+these\s+documents\s+carefully,\s+as\s+they\s+
        describe\s+your\s+rights\s+and\s+restrictions\s+with\s+respect\s+
        to\s+this\s+document\.\s*"""

COPYRIGHT_IETF = re.compile(
    COPYRIGHT_ALT_STREAMS_PART
    + r"""Code\s+Components\s+extracted\s+from\s+
        this\s+document\s+must\s+include\s+(Simplified|Revised)\s+BSD\s+
        License\s+text\s+as\s+described\s+in\s+Section\s+4\.e\s+of\s+
        the\s+Trust\s+Legal\s+Provisions\s+and\s+are\s+provided\s+
        without\s+warranty\s+as\s+described\s+in\s+the\s+
        (Simplified|Revised)\s+BSD\s+License\.\s*""",
    re.VERBOSE,
)

COPYRIGHT_ALT_STREAMS = re.compile(
    COPYRIGHT_ALT_STREAMS_PART,
    re.VERBOSE,
)

NO_MOD_RFC = re.compile(
    r"""This\s+document\s+may\s+not\s+be\s+modified,\s+and\s+derivative\s+
    works\s+of\s+it\s+may\s+not\s+be\s+created,\s+except\s+to\s+format\s+it\s+
    for\s+publication\s+as\s+an\s+RFC\s+or\s+to\s+translate\s+it\s+into\s+
    languages\s+other\s+than\s+English\.\s*""",
    re.VERBOSE,
)

NO_MOD_NO_RFC = re.compile(
    r"""This\s+document\s+may\s+not\s+be\s+modified,\s+and\s+derivative\s+
    works\s+of\s+it\s+may\s+not\s+be\s+created,\s+and\s+it\s+may\s+not\s+be\s+
    published\s+except\s+as\s+an\s+Internet-Draft\.\s*""",
    re.VERBOSE,
)

PRE_5378 = re.compile(
    r"""This\s+document\s+may\s+contain\s+material\s+from\s+IETF\s+Documents\s+
    or\s+IETF\s+Contributions\s+published\s+or\s+made\s+publicly\s+available\s+
    before\s+November\s+10,\s+2008\.\s+
    The\s+person\(s\)\s+controlling\s+the\s+copyright\s+in\s+some\s+of\s+this\s+
    material\s+may\s+not\s+have\s+granted\s+the\s+IETF\s+Trust\s+the\s+right\s+
    to\s+allow\s+modifications\s+of\s+such\s+material\s+outside\s+the\s+IETF\s+
    Standards\s+Process\.\s+
    Without\s+obtaining\s+an\s+adequate\s+license\s+from\s+the\s+person\(s\)\s+
    controlling\s+the\s+copyright\s+in\s+such\s+materials,\s+this\s+document\s+
    may\s+not\s+be\s+modified\s+outside\s+the\s+IETF\s+Standards\s+Process,\s+
    and\s+derivative\s+works\s+of\s+it\s+may\s+not\s+be\s+created\s+outside\s+
    the\s+IETF\s+Standards\s+Process,\s+except\s+to\s+format\s+it\s+for\s+
    publication\s+as\s+an\s+RFC\s+or\s+to\s+translate\s+it\s+into\s+languages\s+
    other\s+than\s+English\.\s*""",
    re.VERBOSE,
)
