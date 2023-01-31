"""ietf-reviewtool metadata module"""

import logging
import re

import num2words  # type: ignore

from .doc import Doc
from .review import IetfReview
from .util.fetch import fetch_meta
from .util.text import word_join
from .references import STATUS_RANK


def check_meta(
    doc: Doc, review: IetfReview, datatracker: str, log: logging.Logger
) -> None:
    """
    Check document metadata for issues.

    @param      doc          The document
    @param      review       The IETF review to comment upon
    @param      datatracker  The datatracker
    @param      log          The log

    @return     { description_of_the_return_value }
    """

    level = doc.meta["std_level"] or doc.meta["intended_std_level"]
    if not level:
        review.discuss(
            "Missing RFC status",
            "Datatracker does not record an intended RFC status for this document.",
        )
    else:
        if doc.status.lower() != level.lower() and (
            level.lower() != "proposed standard"
            or doc.status.lower() != "standards track"
        ):
            review.discuss(
                "Unclear RFC status",
                f'Intended RFC status in datatracker is "{level}", but '
                f'document says "{doc.status}".',
            )
            # continue checking with the "higher" of the two statuses
            if STATUS_RANK[level.lower()] > STATUS_RANK[doc.status.lower()]:
                doc.status = level
                log.info(f"Conflicting status info; checking as {doc.status}")

    num_authors = len(doc.meta["authors"])
    if num_authors > 5:
        review.comment(
            "Too many authors",
            f"The document has {num2words.num2words(num_authors)} "
            "authors, which exceeds the "
            "recommended author limit. Has the sponsoring AD "
            "agreed that this is appropriate?",
        )

    iana_review_state = (
        doc.meta["iana_review_state"] if "iana_review_state" in doc.meta else None
    )
    if iana_review_state:
        if re.match(r".*Not\s+OK", iana_review_state, flags=re.IGNORECASE):
            review.discuss(
                "IANA",
                "This document seems to have unresolved IANA issues. "
                "Holding a DISCUSS for IANA, so we can determine next steps during "
                "the telechat.",
            )
        elif re.match(r".*Review\s+Needed", iana_review_state, flags=re.IGNORECASE):
            review.comment(
                "IANA",
                "The IANA review of this document seems to not have concluded yet.",
            )

    consensus = doc.meta["consensus"] if "consensus" in doc.meta else None
    if consensus is None:
        review.comment(
            "Unclear consensus",
            "The datatracker state does not indicate whether the "
            "consensus boilerplate should be included in this document.",
        )

    stream = doc.meta["stream"] if "stream" in doc.meta else None
    if stream != "IETF":
        review.comment(
            "Unusual stream",
            "This does not seem to be an IETF-stream document.",
        )

    for rel, rel_docs in doc.relationships.items():
        if rel == "updates":
            missing_docs = []
            for rel_doc in rel_docs:
                if not re.search(r"RFC\s*" + rel_doc, doc.abstract):
                    missing_docs.append(rel_doc)
            if missing_docs:
                updates = word_join(rel_docs, prefix="RFC")
                review.discuss(
                    'Missing "Updates" explanation',
                    f"This document updates {updates}, but does not seem "
                    f"to include explanatory text about this in the "
                    f"abstract.",
                )

        for rel_doc in rel_docs:
            meta = fetch_meta(datatracker, "rfc" + rel_doc, log)
            level = (
                meta["std_level"] or meta["intended_std_level"] if meta else "Unknown"
            )
            if not relationship_ok(doc.status, level):
                review.discuss(
                    f"{rel.capitalize()} issue",
                    f"This {doc.status} document {rel} RFC{rel_doc}, "
                    f"which is {level}.",
                )


def relationship_ok(status: str, level: str) -> bool:
    """
    Check if a document with the given intended status can have a relationship with a
    document of the given level.

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
