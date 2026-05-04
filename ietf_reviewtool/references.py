"""ietf-reviewtool references module"""

import asyncio
import logging
import re

from .doc import Doc
from .review import IetfReview
from .util.fetch import (
    fetch_docs_in_last_call_text,
    fetch_dt_async,
    fetch_meta_async,
    run_async,
)
from .util.text import basename, untag, word_join
from .util.utils import REFERENCE_KINDS, change_dir, die, duplicates, get_latest

STATUS_RANK = {
    "internet standard": 3,
    "full standard": 3,
    "best current practice": 3,
    "draft standard": 2,
    "proposed standard": 1,
    "standards track": 1,
    "experimental": 0,
    "informational": 0,
    "historic": 0,
    "unknown": 0,
}


def _parse_ref_doc(ref_doc: str) -> tuple[str, str | None] | None:
    "Parse a ref_doc string into (docname, rev). Returns None if not an RFC or draft."
    name = re.search(r"^(rfc\d+|draft-[-a-z\d_.]+)", ref_doc) if ref_doc else None
    if not name:
        return None
    draft = re.search(r"^(draft-.*)-(\d{2,})$", name.group(0))
    if draft:
        return draft.group(1), basename(draft.group(2))
    return re.sub(r"rfc0*(\d+)", r"rfc\1", name.group(0)), None


def _docname_from_ref(ref_doc: str) -> str | None:
    result = _parse_ref_doc(ref_doc)
    return result[0] if result else None


async def _prefetch_all_async(
    doc: Doc, datatracker: str, log: logging.Logger
) -> tuple[dict, dict, dict, list]:
    """Fire all ref metadata, obs, and downref requests in one gather."""
    docnames: set[str] = set()
    for kind in REFERENCE_KINDS:
        for _tag, ref_docs in doc.references[kind]:
            for ref_doc in ref_docs:
                docname = _docname_from_ref(ref_doc)
                if docname:
                    docnames.add(docname)

    obs_q = "doc/relateddocument/?relationship__slug=obs&target__name="
    downrefs_q = "doc/relateddocument/?relationship=downref-approval&limit=0"

    # Single gather: meta + obs + downrefs all at once
    meta_keys = [("meta", n) for n in docnames]
    obs_keys = [("obs", n) for n in docnames]
    all_keys = meta_keys + obs_keys + [("downrefs", None)]
    coros = (
        [fetch_meta_async(datatracker, n, log) for n in docnames]
        + [fetch_dt_async(datatracker, obs_q + n, log) for n in docnames]
        + [fetch_dt_async(datatracker, downrefs_q, log)]
    )
    results = await asyncio.gather(*coros)
    by_key = dict(zip(all_keys, results))

    meta = {n: by_key[("meta", n)] for n in docnames}
    obs = {n: by_key[("obs", n)] for n in docnames}
    downrefs_raw = by_key[("downrefs", None)]
    downrefs = [re.sub(r".*(rfc\d+).*", r"\1", d["target"]) for d in downrefs_raw]

    # Source fetches depend on obs results — second gather
    source_keys = [
        (n, o["source"]) for n, obs_list in obs.items() if obs_list for o in obs_list
    ]
    obs_rfcs: dict[str, list] = {}
    if source_keys:
        src_results = await asyncio.gather(
            *[fetch_dt_async(datatracker, src, log) for _, src in source_keys]
        )
        for (n, _src), result in zip(source_keys, src_results):
            if result and "rfc" in result:
                obs_rfcs.setdefault(n, []).append(result["rfc"])

    return meta, obs, obs_rfcs, downrefs


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
    meta_cache, obs_cache, obs_rfcs_cache, downrefs_in_registry = run_async(
        _prefetch_all_async(doc, datatracker, log)
    )
    if doc.path:
        with change_dir(doc.path):
            docs_in_lc = (
                fetch_docs_in_last_call_text(
                    doc.meta["name"] + "-" + doc.meta["rev"] + ".txt", log
                )
                if doc.meta
                else []
            )
    else:
        docs_in_lc = []

    # remove self-mentions from extracted references in the text
    doc.references["text"] = [
        r for r in doc.references["text"] if not untag(r).startswith(doc.name)
    ]

    quote = "`" if review.mkd else ""

    # check for duplicates
    for kind in REFERENCE_KINDS:
        if not doc.references[kind]:
            continue

        tags = [x[0] for x in doc.references[kind]]
        tgts = [next(iter(x[1])) if x[1] else None for x in doc.references[kind]]
        dupes = duplicates(tags)
        if dupes:
            review.nit(
                "Duplicate references",
                f"Duplicate {kind} references: "
                f"{word_join(dupes, prefix=quote, suffix=quote)}.",
            )

        dupes = {d for d in duplicates(tgts) if d is not None}
        if dupes:
            tags = [t[0] for t in doc.references[kind] if t[1] in dupes]
            review.nit(
                "Duplicate references",
                f"Duplicate {kind} references to: "
                f"{word_join(dupes, prefix=quote, suffix=quote)}.",
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
            f"{word_join(norm & info, prefix=quote, suffix=quote)}.",
        )

    if in_text - both:
        ref_list = word_join(in_text - both, prefix=quote, suffix=quote)
        review.comment(
            "Missing references",
            (
                "No reference entries found for these items, "
                f"which were mentioned in the text: {ref_list}."
            ),
        )

    if both - in_text:
        ref_list = word_join(both - in_text, prefix=quote, suffix=quote)
        review.nit("Uncited references", f"Uncited references: {ref_list}.")

    def ref_in(ref: str, refs: list) -> bool:
        return any(
            re.search(ref, name) for _, ref_docs in refs for name in (ref_docs or [])
        )

    for rel, rel_docs in doc.relationships.items():
        for rel_doc in rel_docs:
            ref = f"rfc{rel_doc}"
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

    for kind in REFERENCE_KINDS:
        for tag, ref_docs in doc.references[kind]:
            for ref_doc in ref_docs:
                parsed = _parse_ref_doc(ref_doc)
                if not parsed:
                    log.debug(
                        "No metadata available for %s reference %s",
                        kind,
                        tag,
                    )
                    if kind == "normative" and doc.status_lower not in [
                        "informational",
                        "experimental",
                    ]:
                        review.comment(
                            "DOWNREFs",
                            f"Possible DOWNREF from this {doc.status} doc "
                            f"to {quote}{tag}{quote}. If so, the IESG needs to "
                            "approve it.",
                        )
                    continue

                docname, rev = parsed
                ref_meta = meta_cache.get(docname)
                display_name = re.sub(r"rfc", r"RFC", docname)

                latest = ref_meta and get_latest(ref_meta["rev_history"], "published")
                if latest and latest["rev"] and rev and latest["rev"] > rev:
                    if latest["rev"].startswith("rfc"):
                        review.nit(
                            "Outdated references",
                            f"Document references {quote}{display_name}{quote}, but "
                            f"that has been published as {quote}{latest['rev'].upper()}"
                            "{quote}.",
                        )
                    else:
                        review.nit(
                            "Outdated references",
                            f"Document references {quote}{docname}-{rev}{quote}, but "
                            f"{quote}-{latest['rev']}{quote} is the latest "
                            f"available revision.",
                        )

                if ref_meta and doc.status_lower not in [
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
                                f"Possible DOWNREF {quote}{tag}{quote} from this "
                                f"{level} to {quote}{display_name}{quote}.",
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

                if obs_cache.get(docname):
                    ob_bys = obs_rfcs_cache.get(docname, [])
                    if ob_bys:
                        ob_rfcs = word_join(ob_bys, prefix=f"{quote}RFC", suffix=quote)
                        review.nit(
                            "Outdated references",
                            f"Reference {quote}{tag}{quote} to "
                            f"{quote}{display_name}{quote}, "
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


def fetch_downrefs(datatracker: str, log: logging.Logger) -> list[str]:
    downrefs = run_async(
        fetch_dt_async(
            datatracker,
            "doc/relateddocument/?relationship=downref-approval&limit=0",
            log,
        )
    )
    return [re.sub(r".*(rfc\d+).*", r"\1", d["target"]) for d in downrefs]
