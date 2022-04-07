import textwrap
import difflib
import re

from .doc import Doc
from .util.docposition import DocPosition
from .util.format import fmt_nit, fmt_comment


def strip_nits_from_diff(diff: list) -> list:
    """
    Return a version of the passed diff with all lines related to nits removed.

    @param      diff  The diff to strip nits from

    @return     A diff with all nits removed.
    """
    prev = None
    continue_again = False
    result = []

    for num, cur in enumerate(diff):
        if continue_again:
            continue_again = False
            continue

        kind = cur[0]

        if cur in ["+ \n", "- \n"]:
            prev = kind
            continue

        nxt = diff[num + 1] if num < len(diff) - 1 else None
        nxt_kind = nxt[0] if nxt else None

        if kind == "+":
            if nxt_kind == "?":
                continue_again = True
                prev = kind
                continue
            if prev == "?":
                prev = kind
                continue

        if kind == "?" and prev in ["+", "-"]:
            prev = kind
            continue

        if kind == "-":
            cur = re.sub(r".(.*)", r" \1", cur)

        result.append(cur)
        prev = kind
    return result


class IetfReview:
    boilerplate = {
        "nit": (
            "All comments below are about very minor potential issues "
            "that you may choose to address in some way - or ignore - "
            "as you see fit. Some were flagged by automated tools (via "
            "https://github.com/larseggert/ietf-reviewtool), so there "
            "will likely be some false positives. "
            "There is no need to let me know what you did "
            "with these suggestions."
        )
    }

    def __init__(self, doc: Doc, width: int = 79):
        self.width = width
        self.__data = {"discuss": [], "comment": [], "nit": []}

        diff = list(
            difflib.ndiff(
                doc.orig_lines, doc.current_lines, linejunk=None, charjunk=None
            )
        )
        self.gather_nits(diff)
        diff = strip_nits_from_diff(diff)
        self.gather_comments(diff)

    def __add(self, content: str, kind: str, wrap: bool, end: str) -> None:
        assert isinstance(content, str)
        if wrap:
            content = self.__wrap_para(content, end)
        self.__data[kind].append(content)

    def discuss(self, content: str, wrap: bool = True, end: str = "\n") -> None:
        "Add a discuss position to the review."
        self.__add(content, "discuss", wrap, end)

    def comment(self, content: str, wrap: bool = True, end: str = "\n") -> None:
        "Add a comment to the review."
        self.__add(content, "comment", wrap, end)

    def nit(self, content: str, wrap: bool = True, end: str = "\n") -> None:
        "Add a nit to the review."
        self.__add(content, "nit", wrap, end)

    def discuss_bullets(self, header: str, bullets: list[str], end: str = "\n") -> None:
        "Add a discuss bullet list to the review."
        content = self.__bulletize(header, bullets)
        self.__add(content, "discuss", wrap=False, end=end)

    def comment_bullets(self, header: str, bullets: list[str], end: str = "\n") -> None:
        "Add a comment bullet list to the review."
        content = self.__bulletize(header, bullets)
        self.__add(content, "comment", wrap=False, end=end)

    def nit_bullets(self, header: str, bullets: list[str], end: str = "\n") -> None:
        "Add a nit bullet list to the review."
        content = self.__bulletize(header, bullets)
        self.__add(content, "nit", wrap=False, end=end)

    def __str__(self) -> str:
        out = []
        for category, content in self.__data.items():
            if not content:
                continue
            out.append("\n" + "-" * self.width)
            out.append(category.upper())
            out.append("-" * self.width + "\n")
            if self.boilerplate.get(category, None):
                out.append(self.__wrap_para(self.boilerplate[category], end="\n"))
            out.extend(content)
        return "\n".join(out)

    def __or__(self, other):
        for key, value in other.items():
            if key in self.__data:
                self.__data[key].extend(value)
        return self

    def __wrap_para(self, text: str, end: str) -> str:
        """
        Return a wrapped version of the text, ending with end.

        @param      text   The text to wrap
        @param      end    The end to add to the text

        @return     Wrapped version of text followed by end.
        """
        return textwrap.fill(text, width=self.width, break_on_hyphens=False) + end

    def __bulletize(self, header: str, bullets: list[str]) -> str:
        """
        Return a wrapped version of the text, ending with end, as a bullet item.

        @param      text   The text to wrap
        @param      end    The end to add to the text

        @return     Wrapped version of text followed by end, formatted as bullet
                    item.
        """
        out = [self.__wrap_para(header, end="\n")]
        for bullet in bullets:
            out.append(
                textwrap.fill(
                    bullet,
                    width=self.width,
                    initial_indent=" * ",
                    subsequent_indent="   ",
                    break_on_hyphens=False,
                )
            )
        return "\n".join(out) + "\n"

    def gather_nits(self, diff: list) -> None:
        """
        Return a list of prefixed nits from the current diff.

        @param      self  The IetfReview object
        @param      diff  The diff to extract nits from

        @return     None
        """
        changed = {"+": [], "-": []}
        indicator = {"+": [], "-": []}
        doc_pos = DocPosition()
        prev = None

        for num, cur in enumerate(diff):
            # print(cur, end="")
            kind = cur[0]

            nxt = diff[num + 1] if num < len(diff) - 1 else None
            nxt_kind = nxt[0] if nxt else None

            if cur in ["+ \n", "- \n"]:
                prev = kind
                if nxt:
                    continue

            if kind in ["+", "-"] and nxt_kind == "?":
                changed[kind].append(cur)

            elif kind == "?" and prev in ["+", "-"]:
                indicator[prev].append(cur)

            elif kind in ["-"]:  # this would catch nits: ["+", "-"]:
                changed[kind].append(cur)
                indicator[kind].append(None)

            elif kind == "-" and nxt_kind == "+":
                changed[kind].append(cur)
                indicator[kind].append(None)

            elif kind == "+" and prev == "-":
                changed[kind].append(cur)
                indicator[kind].append(None)

            elif changed["-"] or changed["+"]:
                self.nit(fmt_nit(changed, indicator, doc_pos), wrap=False)

            elif not nxt and kind != " ":
                changed[kind].append(cur)

            if nxt:
                doc_pos.update(nxt, cur)

            prev = kind

        if changed["-"] or changed["+"]:
            self.nit(fmt_nit(changed, indicator, doc_pos), wrap=False)

    def gather_comments(self, diff: list) -> None:
        """
        Gather comments in diff into review.

        @param      diff    A diff with nits removed (by strip_nits_from_diff)
        @param      review  IETF Review object.
        """
        doc_pos = DocPosition()
        item = {}

        for num, cur in enumerate(diff):
            nxt = diff[num + 1] if num < len(diff) - 1 else None

            start = re.search(r"^\+ (?:(DISCUSS|COMMENT|NIT):?)?\s*(.*)", cur)
            if start and start.group(1):
                if "cat" in item:
                    getattr(self, item["cat"])(fmt_comment(item, doc_pos), wrap=False)
                item["cat"] = start.group(1).lower()
                item["ctx"] = []
                item["ctx_ok"] = start.group(2) != ""
                item["txt"] = []
                item["txt_ok"] = False
                if item["ctx_ok"]:
                    cur = "+ " + start.group(2) + "\n"
                else:
                    continue

            if "txt_ok" in item:
                kind = cur[0]
                if item["ctx_ok"] is False:
                    if kind != " ":
                        item["txt"].append(cur)
                        item["ctx_ok"] = True
                    else:
                        item["ctx"].append(cur)
                else:
                    if kind != "+":
                        item["txt_ok"] = True
                    else:
                        item["txt"].append(cur)

                if item["txt_ok"] or nxt is None:
                    getattr(self, item["cat"])(fmt_comment(item, doc_pos), wrap=False)

            doc_pos.update(nxt, cur)
