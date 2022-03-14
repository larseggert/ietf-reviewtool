import itertools
import logging
import re
import yaml

from .util.fetch import fetch_url
from .util.text import bulletize, word_join, wrap_para


def check_inclusivity(
    text: str, width: int, log: logging.Logger, verbose: bool = False
) -> dict:
    """
    Check document terminology for potential inclusivity issues.

    @param      text   The document text
    @param      width  The width the issues should be wrapped to

    @return     List of possible inclusivity issues.
    """
    review = {"discuss": [], "comment": [], "nit": []}
    isb_url = (
        # "file:///Users/lars/Documents/Code/terminology/"
        "https://raw.githubusercontent.com/ietf/terminology/main/"
        ".github/in-solidarity.yml"
    )
    isb_yaml = fetch_url(isb_url, log)

    if not isb_yaml:
        log.info("Could not fetch in-solidarity.yml from %s", isb_url)
        return review
    rules = yaml.safe_load(isb_yaml)

    result = {}
    for name, data in rules["rules"].items():
        for pattern in data["regex"]:
            pattern = re.sub(r"/(.*)/.*", r"((\1)\\w*)", pattern)
            hits = re.findall(pattern, text, flags=re.IGNORECASE)
            if hits:
                hits = set(map(str.lower, itertools.chain(*hits)))
                result[name] = (
                    [hit for hit in hits if hit != ""],
                    pattern,
                    data["alternatives"] if "alternatives" in data else None,
                )

    if result:
        review["comment"].append(
            wrap_para(
                "Found terminology that should be reviewed for inclusivity; "
                "see https://www.rfc-editor.org/part2/#inclusive_language "
                "for background and more guidance:",
                width=width,
                end="\n\n",
            )
        )
        for name, match in result.items():
            terms = word_join(match[0], prefix='"', suffix='"')
            msg = f'Term{"s" if len(match[0]) > 1 else ""} {terms}; '
            if match[2]:
                msg += "alternatives might be "
                msg += ", ".join([f'"{a}"' for a in match[2]])
            else:
                msg += "but I have no suggestion for an alternative"
            if verbose:
                msg += f' (matched "{name}" rule, pattern {match[1]})'
            review["comment"].extend(bulletize(msg, width=width, end=".\n\n"))

    return review
