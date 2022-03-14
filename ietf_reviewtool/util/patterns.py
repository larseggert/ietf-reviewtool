import re

# pattern matching section headings
SECTION_PATTERN = re.compile(
    r"""^(?:[\- ]\s)?(Abstract|Status\sof\sThis\sMemo|Copyright\sNotice|
        Editorial\sNote|Table\sof\sContents|
        (?:(?:Non-)Normative\s|Informative\s)?References?|
        Author(?:'?s?'?)?\sAddress(?:es)?|
        (?:Appendix\s+)?[\dA-Z]+(?:\.\d+)*\.?\s|
        \d+(?:\.\d+)*\.?)(.*)""",
    re.VERBOSE,
)
