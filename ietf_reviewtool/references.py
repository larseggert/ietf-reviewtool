"""ietf-reviewtool references module"""

import logging
import re

from .review import IetfReview
from .util.fetch import fetch_meta, fetch_docs_in_last_call_text, fetch_dt
from .util.text import untag, word_join, basename
from .util.utils import duplicates, get_latest, die


def check_refs(
    datatracker: str,
    refs: dict,
    rels: dict,
    name: str,
    status: str,
    meta: dict,
    text: str,
    review: IetfReview,
    log: logging.Logger,
) -> None:
    """
    Check the references.

    @param      datatracker  The datatracker URL to use
    @param      refs         The references to check
    @param      rels         The relationship of this document to others
    @param      name         The name of this document.
    @param      status       The standards level of the given document
    @param      meta         The metadata
    @param      text         The document text
    @param      review       The IETF review to comment upon
    @param      log          The log to write to
    """
    downrefs_in_registry = fetch_downrefs(datatracker, log)
    docs_in_lc = (
        fetch_docs_in_last_call_text(meta["name"] + "-" + meta["rev"] + ".txt", log)
        if meta
        else []
    )

    # remove self-mentions from extracted references in the text
    refs["text"] = [r for r in refs["text"] if not untag(r).startswith(name)]

    # check for duplicates
    for kind in ["normative", "informative"]:
        if not refs[kind]:
            continue
        tags, tgts = zip(*refs[kind])
        dupes = duplicates(tags)
        if dupes:
            review.nit(
                f"Duplicate {kind} references: {word_join(dupes)}.",
            )

        dupes = duplicates(tgts)
        if dupes:
            tags = [t[0] for t in refs[kind] if t[1] in dupes]
            review.nit(
                f"Duplicate {kind} references to: {word_join(dupes)}.",
            )

    norm = set(e[0] for e in refs["normative"])
    info = set(e[0] for e in refs["informative"])
    both = norm | info
    in_text = {"[" + r + "]" for r in {untag(r) for r in refs["text"]}}

    if norm & info:
        review.nit(
            "Reference entries duplicated in both normative and "
            f"informative sections: {word_join(list(norm & info))}.",
        )

    if in_text - both:
        ref_list = word_join(list(in_text - both))
        review.comment(f"No reference entries found for: {ref_list}.")

    if both - in_text:
        ref_list = word_join(list(both - in_text))
        review.nit(f"Uncited references: {ref_list}.")

    for rel, docs in rels.items():
        for doc in docs:
            ref = f"rfc{doc}"
            in_normative = ref in [x[1] for x in refs["normative"]]
            in_informative = ref in [x[1] for x in refs["informative"]]

            if not in_normative and not in_informative:
                review.comment(
                    f"Document {rel} RFC{doc}, but does not cite it as a "
                    f"reference.",
                )

    level = meta and (meta["std_level"] or meta["intended_std_level"])
    if not level:
        # if we have no level from the metadata, see if the document has one
        level = re.search(r"^Intended status: (.*)\s{2,}", text, flags=re.MULTILINE)
        level = level[1].rstrip() if level else "unknown"

    for kind in ["normative", "informative"]:
        for tag, doc in refs[kind]:
            if doc:
                name = re.search(r"^(rfc\d+|draft-[-a-z\d_.]+)", doc)
            if not doc or not name:
                log.debug(
                    "No metadata available for %s reference %s",
                    kind,
                    tag,
                )
                if kind == "normative" and status.lower() not in [
                    "informational",
                    "experimental",
                ]:
                    review.comment(
                        f"Possible DOWNREF from this {status} doc "
                        f"to {tag}. If so, the IESG needs to approve it.",
                    )
                continue

            draft_components = re.search(r"^(draft-.*)-(\d{2,})$", name.group(0))
            rev = None
            if draft_components:
                name = draft_components.group(1)
                rev = draft_components.group(2)
            else:
                name = re.sub(r"rfc0*(\d+)", r"rfc\1", name.group(0))
            ref_meta = fetch_meta(datatracker, basename(name), log)
            display_name = re.sub(r"rfc", r"RFC", name)

            latest = ref_meta and get_latest(ref_meta["rev_history"], "published")
            if latest and latest["rev"] and rev and latest["rev"] > rev:
                if latest["rev"].startswith("rfc"):
                    review.nit(
                        f"Document references {display_name}, but that "
                        f"has been published as {latest['rev'].upper()}.",
                    )
                else:
                    review.nit(
                        f"Document references {name}-{rev}, but "
                        f"-{latest['rev']} is the latest "
                        f"available revision.",
                    )

            if status.lower() not in ["informational", "experimental"]:
                ref_level = (
                    ref_meta["std_level"] or ref_meta["intended_std_level"] or "unknown"
                )
                if (
                    is_downref(level, kind, ref_level, log)
                    and name not in downrefs_in_registry
                    and name not in docs_in_lc
                ):
                    if ref_level is None:
                        review.comment(
                            f"Possible DOWNREF {tag} from this {level} "
                            f"to {display_name}.",
                        )
                    else:
                        msg = f"DOWNREF {tag} from this {level} to "
                        if ref_level != "unknown":
                            msg += f"{ref_level} {display_name}."
                        else:
                            msg += f"{display_name} of unknown standards level."
                        msg += (
                            " (For IESG discussion. "
                            "It seems this DOWNREF was not mentioned in "
                            "the Last Call and also seems to not appear "
                            "in the DOWNREF registry.)"
                        )
                        review.comment(msg)

            obsoleted_by = fetch_dt(
                datatracker,
                "doc/relateddocument/?relationship__slug=obs&target__name=" + name,
                log,
            )
            if obsoleted_by:
                ob_bys = []
                for obs in obsoleted_by:
                    obs_by = fetch_dt(datatracker, obs["source"], log)
                    if "rfc" in obs_by:
                        ob_bys.append(obs_by["rfc"])

                ob_rfcs = word_join(ob_bys, prefix="RFC")
                review.nit(
                    f"Reference {tag} to {display_name}, "
                    f"which was obsoleted by {ob_rfcs} "
                    f"(this may be on purpose).",
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
        rank = {
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

        if ref_level == "best current practice":
            return rank[level] < 1

        return rank[level] > rank[ref_level]

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
