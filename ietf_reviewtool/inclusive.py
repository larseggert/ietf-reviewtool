"""ietf-reviewtool inclusive module"""

import itertools
import logging
import re
import yaml

from .doc import Doc
from .review import IetfReview
from .util.fetch import fetch_url
from .util.text import word_join, unfold


def check_inclusivity(
    doc: Doc, review: IetfReview, log: logging.Logger, verbose: bool = False
) -> None:
    """
    Check document terminology for potential inclusivity issues.

    @param      doc      The document
    @param      review   The IETF Review to make comments upon
    @param      log      The log
    @param      verbose  The verbose

    @return     { description_of_the_return_value }
    """
    isb_url = (
        # "file:///Users/lars/Documents/Code/terminology/"
        "https://raw.githubusercontent.com/ietf/terminology/main/"
        ".github/in-solidarity.yml"
    )
    isb_yaml = fetch_url(isb_url, log)

    if not isb_yaml:
        log.info("Could not fetch in-solidarity.yml from %s", isb_url)
        return
    rules = yaml.safe_load(isb_yaml)

    result = {}
    for name, data in rules["rules"].items():
        for pattern in data["regex"]:
            pattern = re.sub(r"/(.*)/.*", r"((\1)\\w*)", pattern)
            matches = re.findall(pattern, unfold(doc.orig), flags=re.IGNORECASE)
            if matches:
                hits = set(map(str.lower, itertools.chain(*matches)))
                result[name] = (
                    [hit for hit in hits if hit != ""],
                    pattern,
                    data["alternatives"] if "alternatives" in data else None,
                )

    if result:
        comment_header = (
            "Found terminology that should be reviewed for inclusivity; "
            "see https://www.rfc-editor.org/part2/#inclusive_language "
            "for background and more guidance:"
        )
        comment_items = []
        quote = "`" if review.mkd else '"'
        for name, match in result.items():
            terms = word_join(match[0], prefix=quote, suffix=quote)
            msg = f'Term{"s" if len(match[0]) > 1 else ""} {terms}; '
            if match[2]:
                msg += "alternatives might be "
                msg += ", ".join([f"{quote}{a}{quote}" for a in match[2]])
            else:
                msg += "but I have no suggestion for an alternative"
            if verbose:
                msg += f" (matched {quote}{name}{quote} rule, pattern {match[1]})"
            comment_items.append(msg)
        review.comment_bullets("Inclusive language", comment_header, comment_items)
