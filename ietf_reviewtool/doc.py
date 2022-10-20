"""ietf-reviewtool document  module"""

import logging
import os
import re
import tempfile

from .util.docposition import SECTION_PATTERN
from .util.fetch import get_items, fetch_meta
from .util.text import basename, revision, unfold, untag, extract_urls
from .util.utils import read


class Doc:
    "Class to handle a document to review."
    name: str
    status: str
    orig: str
    orig_lines: list[str]
    current: str
    current_lines: list[str]
    relationships: dict
    abstract: str
    meta: dict
    is_id: bool
    references: dict

    def __init__(self, item: str, log: logging.Logger, datatracker: str):
        self.name = basename(item)
        self.revision = revision(item)
        self.path = os.path.dirname(item)
        with tempfile.TemporaryDirectory() as tmp:
            current_directory = os.getcwd()
            log.debug("tmp dir %s", tmp)
            self.orig = ""
            if item != "/dev/stdin":
                os.chdir(tmp)
                orig_item = os.path.basename(item)
                get_items([orig_item], log, datatracker)
                self.orig = read(orig_item, log)
                os.chdir(current_directory)
            self.current = read(item, log)
            if not self.orig:
                log.error(
                    "No original for %s, cannot review, only performing checks",
                    item,
                )
                self.orig = self.current

        self.orig_lines = self.orig.splitlines(keepends=True)
        self.current_lines = self.current.splitlines(keepends=True)

        # difflib can't deal with single lines it seems
        if len(self.orig_lines) == 1:
            self.orig_lines.append("\n")
        if len(self.current_lines) == 1:
            self.current_lines.append("\n")

        # set status
        status = re.search(
            r"^(?:[Ii]ntended )?[Ss]tatus:\s*((?:\w+\s)+)",
            self.orig,
            re.MULTILINE,
        )
        self.status = status.group(1).strip() if status else ""

        # extract relationships
        self.relationships = {}
        rel_pat = {"updates": r"[Uu]pdates", "obsoletes": r"[Oo]bsoletes"}
        for rel in ["updates", "obsoletes"]:
            match = re.search(
                r"^"
                + rel_pat[rel]
                + r":\s*((?:(?:RFC\s*)?\d{3,},?\s*)+)"
                + r"(?:.*[\n\r\s]+((?:(?:RFC\s*)?\d{3,},?\s*)+)?)?",
                self.orig,
                re.MULTILINE,
            )
            if match:
                tmp = "".join([group for group in match.groups() if group])
                tmp = re.sub("rfc", "", tmp, flags=re.IGNORECASE)
                tmp = re.sub(r"[,\s]+(\w)", r",\1", tmp)
                self.relationships[rel] = [r for r in tmp.strip().split(",") if r]

        in_abstract = False
        abstract = ""
        for line in self.orig_lines:
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
        self.abstract = unfold(abstract).strip()

        self.meta = fetch_meta(datatracker, self.name, log)
        self.is_id = self.name.startswith("draft-")

        parts = {"text": "", "informative": "", "normative": ""}
        part = "text"
        for line in self.orig_lines:
            pot_sec = SECTION_PATTERN.search(line)
            if pot_sec:
                which = pot_sec.group(0)
                if re.search(
                    r"^(?:(\d\.?)+\s+)?(?:Non-Norm|Inform)(?:ative|ational)\s+References?\s*$",
                    which,
                    flags=re.IGNORECASE,
                ):
                    part = "informative"
                elif re.search(
                    r"^(?:(\d\.?)+\s+)?(Normative\s+)?References?\s*$",
                    which,
                    flags=re.IGNORECASE,
                ):
                    part = "normative"
                else:
                    part = "text"
            parts[part] += line

        refs = {}
        for part, content in parts.items():
            refs[part] = re.findall(
                r"(\[(?:\d+|[a-z]+(?:[-_.]?\w+)*)\]"
                + (r"|RFC\d+|draft-[-a-z\d_.]+" if part == "text" else r"")
                + r")",
                unfold(content),
                flags=re.IGNORECASE,
            )
            refs[part] = list({f"[{untag(ref)}]" for ref in refs[part]})

        self.references = {}
        for part in ["informative", "normative"]:
            self.references[part] = []
            for ref in refs[part]:
                ref_match = re.search(
                    r"\s*" + re.escape(ref) + r"\s+((?:[^\n][\n]?)+)\n",
                    parts[part],
                    re.DOTALL,
                )
                if ref_match:
                    ref_text = unfold(ref_match.group(0))
                    found = False

                    for pat in [r"(draft-[-a-z\d_.]+)", r"((?:RFC|rfc)\d+)"]:
                        match = re.search(pat, ref_text)
                        if match:
                            found = True
                            self.references[part].append((ref, match.group(0).lower()))
                            break

                    if not found:
                        urls = extract_urls(ref_text, log, True, True)
                        self.references[part].append(
                            (ref, urls.pop() if urls else None)
                        )
        self.references["text"] = refs["text"]
