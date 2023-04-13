"""ietf-reviewtool document position module"""

import re

# pattern matching section headings
SECTION_PATTERN = re.compile(
    r"""^(?:[\- ]\s)?(Abstract|Status\sof\sThis\sMemo|Copyright\sNotice|
        Editorial\sNote|Table\sof\sContents|Acknowledge?ments?|
        (?:(?:Non-)Normative\s|Informative\s)?References?|
        Author(?:'?s?'?)?\sAddress(?:es)?|
        (?:Appendix\s+)?[\dA-Z]+(?:\.\d+)*\.?\s|
        \d+(?:\.\d+)*\.?)(.*)""",
    re.VERBOSE,
)


class DocPosition:
    "Class to maintain the current position in a document."
    para_num: int
    sec_title: str
    had_non_numbered_sec: bool

    def __init__(
        self, para_num: int = 0, sec_title: str = "", had_non_numbered_sec: bool = False
    ):
        self.para_num = para_num
        self.sec_title = sec_title
        self.had_non_numbered_sec = had_non_numbered_sec

    def fmt_section_and_paragraph(self, level: str = "") -> str:
        """
        Return a formatted prefix line indicating the current section name, paragraph
        number, and level.

        @param      self   The DocPosition object
        @param      level  The issue level to indicate in the prefix line

        @return     A formatted prefix line.
        """
        line = f"{self.sec_title}, p" if self.sec_title else "P"
        line += f"aragraph {self.para_num}"
        if level:
            line += f", {level}"
        return line + "\n"

    def update(self, nxt: str, cur: str, is_diff: bool = True) -> None:
        """
        Return a list consisting of the current paragraph number and section title,
        based on the next and current lines of text and the current paragraph number and
        section title list.

        @param      self     The DocPosition object
        @param      nxt      The next line in the diff
        @param      cur      The current line in the diff
        @param      is_diff  Indicates if difference

        @return     An updated (paragraph number, section name) list.
        """
        # track paragraphs
        pat = {True: r"^[\- ] +$", False: r"^\s*$"}
        if re.search(pat[is_diff], cur):
            self.para_num += 1
            return

        # track sections
        pot_sec = SECTION_PATTERN.search(cur)
        pat = {True: r"^([\- ] +$|\+ )", False: r"^( *$)"}
        if pot_sec and nxt and (re.search(pat[is_diff], nxt) or len(cur) > 65):
            pot_sec_title = pot_sec.group(1).strip()
            if re.match(r"\d", pot_sec_title):
                if self.had_non_numbered_sec:
                    self.para_num = 0
                    self.sec_title = (
                        "Section " + re.sub(r"(.*)\.$", r"\1", pot_sec_title)
                        if re.match(r"\d", pot_sec_title)
                        else f'"{pot_sec_title}"'
                    )
            else:
                self.para_num = 0
                self.had_non_numbered_sec = True
                self.sec_title = f'"{pot_sec_title}"'
