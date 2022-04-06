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
        self.__data = {"discuss": [], "comment": [], "nit": []}

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
