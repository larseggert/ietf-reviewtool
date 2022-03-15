import textwrap


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

    def __init__(self, width: int = 79):
        self.width = width
        self._data = {"discuss": [], "comment": [], "nit": []}

    def discuss(self, content: str) -> None:
        "Add a discuss position to the review."
        assert isinstance(content, str)
        self._data["discuss"].append(content)

    def comment(self, content: str) -> None:
        "Add a comment to the review."
        assert isinstance(content, str)
        self._data["comment"].append(content)

    def comment_bullets(self, header: str, bullets: list) -> None:
        self._data["comment"].append(self.bulletize(header, bullets))

    def nit(self, content: str) -> None:
        "Add a nit to the review."
        assert isinstance(content, str)
        self._data["nit"].append(content)

    def nit_bullets(self, header: str, bullets: list) -> None:
        self._data["nit"].append(self.bulletize(header, bullets))

    def __str__(self) -> str:
        out = []
        for category, comments in self._data.items():
            if not comments:
                continue
            out.append("-" * self.width)
            out.append(category.upper())
            out.append("-" * self.width)
            if self.boilerplate.get(category, None):
                out.append(self.wrap_para(self.boilerplate[category], end="\n"))
            out.extend(comments)
        return "\n".join(out)

    def __or__(self, other):
        for key, value in other.items():
            if key in self._data:
                self._data[key].extend(value)
        return self

    def wrap_para(self, text: str, end: str = "\n\n") -> str:
        """
        Return a wrapped version of the text, ending with end.

        @param      text   The text to wrap
        @param      end    The end to add to the text

        @return     Wrapped version of text followed by end.
        """
        return textwrap.fill(text, width=self.width, break_on_hyphens=False) + end

    def bulletize(self, header: str, bullets: list) -> str:
        """
        Return a wrapped version of the text, ending with end, as a bullet item.

        @param      text   The text to wrap
        @param      end    The end to add to the text

        @return     Wrapped version of text followed by end, formatted as bullet
                    item.
        """
        out = [header]
        for bullet in bullets:
            out.append(
                textwrap.indent(
                    textwrap.fill(
                        " * " + bullet, self.width - 3, break_on_hyphens=False
                    )
                    + "\n\n"
                    "   ",
                    lambda line: not line.startswith(" * "),
                )
            )
        return "\n".join(out)
