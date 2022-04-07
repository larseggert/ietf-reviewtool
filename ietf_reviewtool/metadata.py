"""ietf-reviewtool metadata module"""

import logging
import re

import num2words

from .review import IetfReview
from .util.fetch import fetch_meta
from .util.docposition import SECTION_PATTERN
from .util.text import (
    unfold,
    word_join,
    get_status,
    get_relationships,
)


def check_meta(
    datatracker: str, text: str, meta: dict, review: IetfReview, log: logging.Logger
) -> None:
    """
    Check document metadata for issues.

    @param      text   The text of the document
    @param      meta   The metadata
    @param      review The IETF review to comment upon
    """

    level = meta["std_level"] or meta["intended_std_level"]
    if not level:
        review.discuss(
            "Datatracker does not record an intended RFC status for this document.",
        )
    else:
        status = get_status(text)
        if status != level and (
            level != "Proposed Standard" or status != "Standards Track"
        ):
            review.discuss(
                f'Intended RFC status in datatracker is "{level}", but '
                f'document says "{status}".',
            )

    num_authors = len(meta["authors"])
    if num_authors > 5:
        review.comment(
            f"The document has {num2words.num2words(num_authors)} "
            "authors, which exceeds the "
            "recommended author limit. I assume the sponsoring AD has "
            "agreed that this is appropriate?",
        )

    iana_review_state = (
        meta["iana_review_state"] if "iana_review_state" in meta else None
    )
    if iana_review_state:
        if re.match(r".*Not\s+OK", iana_review_state, flags=re.IGNORECASE):
            review.comment(
                "This document seems to have unresolved IANA issues.",
            )
        elif re.match(r".*Review\s+Needed", iana_review_state, flags=re.IGNORECASE):
            review.comment(
                "The IANA review of this document seems to not have " "concluded yet.",
            )

    consensus = meta["consensus"] if "consensus" in meta else None
    if consensus is None:
        review.comment(
            "The datatracker state does not indicate whether the "
            "consensus boilerplate should be included in this document.",
        )

    stream = meta["stream"] if "stream" in meta else None
    if stream != "IETF":
        review.comment(
            "This does not seem to be an IETF-stream document.",
        )

    status = get_status(text)
    for rel, docs in get_relationships(text).items():
        if rel == "updates":
            abstract = unfold(extract_abstract(text))
            missing_docs = []
            for doc in docs:
                if not re.search(r"RFC\s*" + doc, abstract):
                    missing_docs.append(doc)
            if missing_docs:
                updates = word_join(docs, prefix="RFC")
                review.discuss(
                    f"This document updates {updates}, but does not seem "
                    f"to include explanatory text about this in the "
                    f"abstract.",
                )

        for doc in docs:
            meta = fetch_meta(datatracker, "rfc" + doc, log)
            level = (
                meta["std_level"] or meta["intended_std_level"] if meta else "Unknown"
            )
            if not relationship_ok(status, level):
                review.discuss(
                    f"This {status} document {rel} RFC{doc}, " f"which is {level}.",
                )


def relationship_ok(status: str, level: str) -> bool:
    """
    Check if a document with the given intended status can have a relationship
    with a document of the given level.

    @param      status  The intended status of a document
    @param      level   The level of a document

    @return     True if the relationship is OK.
    """
    std = [
        "standards track",
        "best current practice",
        "proposed standard",
        "draft standard",
        "internet standard",
    ]
    return (status.lower() in std) or (level.lower() not in std)


def extract_abstract(text: list) -> str:
    """
    Return that abstract of the text .

    @param      text  The text to parse for the abstract

    @return     The abstract.
    """
    in_abstract = False
    abstract = ""
    for line in text.splitlines(keepends=True):
        pot_sec = SECTION_PATTERN.search(line)
        if pot_sec:
            which = pot_sec.group(0)
            if re.search(r"^Abstract", which):
                in_abstract = True
                continue
            if abstract:
                break
        if in_abstract:
            abstract += line
    return abstract
