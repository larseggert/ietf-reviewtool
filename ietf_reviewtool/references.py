"""ietf-reviewtool references module"""

import itertools
import logging
import os
import re

from .doc import Doc
from .review import IetfReview
from .util.fetch import fetch_meta, fetch_docs_in_last_call_text, fetch_dt
from .util.text import untag, word_join, basename
from .util.utils import duplicates, get_latest, die


STATUS_RANK = {
    "internet standard": 3,
    "full standard": 3,
    "best current practice": 3,
    "draft standard": 2,
    "proposed standard": 1,
    "standards track": 1,
    "experimental": 0,
    "informational": 0,
    "unknown": 0,
}


def check_refs(
    doc: Doc,
    review: IetfReview,
    datatracker: str,
    log: logging.Logger,
) -> None:
    """
    Check the references.

    @param      doc          The document
    @param      review       The IETF review to comment upon
    @param      datatracker  The datatracker URL to use
    @param      log          The log to write to

    @return     { description_of_the_return_value }
    """
    downrefs_in_registry = fetch_downrefs(datatracker, log)
    current_directory = os.getcwd()
    if doc.path:
        os.chdir(doc.path)
    docs_in_lc = (
        fetch_docs_in_last_call_text(
            doc.meta["name"] + "-" + doc.meta["rev"] + ".txt", log
        )
        if doc.meta
        else []
    )
    if doc.path:
        os.chdir(current_directory)

    # remove self-mentions from extracted references in the text
    doc.references["text"] = [
        r for r in doc.references["text"] if not untag(r).startswith(doc.name)
    ]

    quote = "`" if review.mkd else ""

    # check for duplicates
    for kind in ["normative", "informative"]:
        if not doc.references[kind]:
            continue

        tags = [x[0] for x in doc.references[kind]]
        tgts = [next(iter(x[1])) if x[1] else None for x in doc.references[kind]]
        dupes = duplicates(tags)
        if dupes:
            review.nit(
                "Duplicate references",
                f"Duplicate {kind} references: "
                f"{word_join(list(dupes), prefix=quote, suffix=quote)}.",
            )

        dupes = duplicates(tgts)
        if None in dupes:
            dupes.remove(None)
        if dupes:
            tags = [t[0] for t in doc.references[kind] if t[1] in dupes]
            review.nit(
                "Duplicate references",
                f"Duplicate {kind} references to: "
                f"{word_join(list(dupes), prefix=quote, suffix=quote)}.",
            )

    norm = set(e[0] for e in doc.references["normative"])
    info = set(e[0] for e in doc.references["informative"])
    both = norm | info
    in_text = {"[" + r + "]" for r in {untag(r) for r in doc.references["text"]}}

    if norm & info:
        review.nit(
            "Duplicate references",
            "Reference entries duplicated in both normative and "
            f"informative sections: "
            f"{word_join(list(norm & info), prefix=quote, suffix=quote)}.",
        )

    if in_text - both:
        ref_list = word_join(list(in_text - both), prefix=quote, suffix=quote)
        review.comment(
            "Missing references",
            (
                "No reference entries found for these items, "
                f"which were mentioned in the text: {ref_list}."
            ),
        )

    if both - in_text:
        ref_list = word_join(list(both - in_text), prefix=quote, suffix=quote)
        review.nit("Uncited references", f"Uncited references: {ref_list}.")

    for rel, rel_docs in doc.relationships.items():
        for rel_doc in rel_docs:
            ref = f"rfc{rel_doc}"

            def ref_in(ref, refs) -> bool:
                return (
                    filter(
                        lambda x: re.search(ref, x),
                        [x[1] for x in refs],
                    )
                    is not None
                )

            in_normative = ref_in(ref, doc.references["normative"])
            in_informative = ref_in(ref, doc.references["informative"])

            if not in_normative and not in_informative:
                review.comment(
                    "Uncited references",
                    f"Document {rel} {quote}RFC{rel_doc}{quote}, "
                    "but does not cite it as a reference, which is a bit odd.",
                )

    level = doc.meta and (doc.meta["std_level"] or doc.meta["intended_std_level"])
    if not level:
        # if we have no level from the metadata, see if the document has one
        level = doc.status if doc.status else "unknown"

    for kind in ["normative", "informative"]:
        for tag, ref_docs in doc.references[kind]:
            for ref_doc in ref_docs:
                if ref_doc:
                    name = re.search(r"^(rfc\d+|draft-[-a-z\d_.]+)", ref_doc)
                if not ref_doc or not name:
                    log.debug(
                        "No metadata available for %s reference %s",
                        kind,
                        tag,
                    )
                    if kind == "normative" and doc.status.lower() not in [
                        "informational",
                        "experimental",
                    ]:
                        review.comment(
                            "DOWNREFs",
                            f"Possible DOWNREF from this {doc.status} doc "
                            f"to {quote}{tag}{quote}. If so, the IESG needs to approve it.",
                        )
                    continue

                draft_components = re.search(r"^(draft-.*)-(\d{2,})$", name.group(0))
                rev = None
                if draft_components:
                    docname = draft_components.group(1)
                    rev = basename(draft_components.group(2))
                else:
                    docname = re.sub(r"rfc0*(\d+)", r"rfc\1", name.group(0))
                ref_meta = fetch_meta(datatracker, docname, log)
                display_name = re.sub(r"rfc", r"RFC", docname)

                latest = ref_meta and get_latest(ref_meta["rev_history"], "published")
                if latest and latest["rev"] and rev and latest["rev"] > rev:
                    if latest["rev"].startswith("rfc"):
                        review.nit(
                            "Outdated references",
                            f"Document references {quote}{display_name}{quote}, but that "
                            f"has been published as {quote}{latest['rev'].upper()}{quote}.",
                        )
                    else:
                        review.nit(
                            "Outdated references",
                            f"Document references {quote}{docname}-{rev}{quote}, but "
                            f"{quote}-{latest['rev']}{quote} is the latest "
                            f"available revision.",
                        )

                if ref_meta and doc.status.lower() not in [
                    "informational",
                    "experimental",
                ]:
                    ref_level = (
                        ref_meta["std_level"]
                        or ref_meta["intended_std_level"]
                        or "unknown"
                    )
                    if (
                        is_downref(level, kind, ref_level, log)
                        and docname not in downrefs_in_registry
                        and docname not in docs_in_lc
                    ):
                        if ref_level is None:
                            review.comment(
                                "DOWNREFs",
                                f"Possible DOWNREF {quote}{tag}{quote} from this {level} "
                                f"to {quote}{display_name}{quote}.",
                            )
                        else:
                            msg = f"DOWNREF {quote}{tag}{quote} from this {level} to "
                            if ref_level != "unknown":
                                msg += f"{ref_level} {quote}{display_name}{quote}."
                            else:
                                msg += (
                                    f"{quote}{display_name}{quote}"
                                    + " of unknown standards level."
                                )
                            msg += (
                                " (For IESG discussion. "
                                "It seems this DOWNREF was not mentioned in "
                                "the Last Call and also seems to not appear "
                                "in the DOWNREF registry.)"
                            )
                            review.comment("DOWNREFs", msg)

                obsoleted_by = fetch_dt(
                    datatracker,
                    "doc/relateddocument/?relationship__slug=obs&target__name="
                    + docname,
                    log,
                )
                if obsoleted_by:
                    ob_bys = []
                    for obs in obsoleted_by:
                        obs_by = fetch_dt(datatracker, obs["source"], log)
                        if "rfc" in obs_by:
                            ob_bys.append(obs_by["rfc"])

                    ob_rfcs = word_join(ob_bys, prefix=f"{quote}RFC", suffix=quote)
                    review.nit(
                        "Outdated references",
                        f"Reference {quote}{tag}{quote} to {quote}{display_name}{quote}, "
                        f"which was obsoleted by {ob_rfcs} "
                        "(this may be on purpose).",
                    )


def is_downref(level: str, kind: str, ref_level: str, log: logging.Logger) -> bool:
    """
    Check if a document reference is allowed (i.e., is not a DOWNREF) for a
    document at a given standards level.

    @param      level      The (intended) standards level of the given document
    @param      kind       The kind of reference (normative or informative.)
    @param      ref_level  The status level of the reference

    @return     True if this is a DOWNREF, True otherwise.
    """
    kind = kind.lower()
    level = level.lower()
    ref_level = ref_level.lower()

    if kind == "normative":
        if level == "best current practice":
            return STATUS_RANK[level] < STATUS_RANK["proposed standard"]
        return STATUS_RANK[level] > STATUS_RANK[ref_level]

    if kind == "informative":
        return False
    die(f"unknown kind {kind}", log)
    return False  # can't be reached, but makes pylint quiet


def fetch_downrefs(datatracker: str, log: logging.Logger) -> list:
    """
    Fetches DOWNREFs from datatracker and returns them as a list.

    @param      datatracker  The datatracker URL to use

    @return     A list of RFC names.
    """
    downrefs = fetch_dt(
        datatracker,
        "doc/relateddocument/?relationship=downref-approval&limit=0",
        log,
    )
    return [re.sub(r".*(rfc\d+).*", r"\1", d["target"]) for d in downrefs]
