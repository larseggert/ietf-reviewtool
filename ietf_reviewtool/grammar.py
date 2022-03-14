import math
import re

import language_tool_python

from .util.format import fmt_section_and_paragraph
from .util.text import unfold, wrap_para, section_and_paragraph


def check_grammar(
    review: str,
    grammar_skip_rules: str,
    width: int,
    show_rule_id: bool = False,
) -> dict:
    """
    Check document grammar.

    @param      review  The document text
    @param      width   The width the issues should be wrapped to

    @return     List of grammar nits
    """
    issues = [
        i
        for i in language_tool_python.LanguageTool("en-US").check(
            unfold("".join(review))
        )
        if i.ruleId
        not in [
            "ADVERTISEMENT_OF_FOR",
            "ALL_OF_THE",
            "ARROWS",
            "BOTH_AS_WELL_AS",
            "COMMA_COMPOUND_SENTENCE",
            "COMMA_PARENTHESIS_WHITESPACE",
            "COPYRIGHT",
            "CURRENCY",
            "DASH_RULE",
            "DATE_FUTURE_VERB_PAST",
            "DATE_NEW_YEAR",
            "EN_QUOTES",
            "EN_UNPAIRED_BRACKETS",
            "ENGLISH_WORD_REPEAT_BEGINNING_RULE",
            "HYPOTHESIS_TYPOGRAPHY",
            "I_LOWERCASE",
            "IN_THE_INTERNET",
            "INCORRECT_POSSESSIVE_FORM_AFTER_A_NUMBER",
            "KEY_WORDS",
            "LARGE_NUMBER_OF",
            "MORFOLOGIK_RULE_EN_US",
            "MULTIPLICATION_SIGN",
            "NUMBERS_IN_WORDS",
            "PLUS_MINUS",
            "PUNCTUATION_PARAGRAPH_END",
            "RETURN_IN_THE",
            "SENTENCE_WHITESPACE",
            "SO_AS_TO",
            "SOME_OF_THE",
            "UNIT_SPACE",
            "UNLIKELY_OPENING_PUNCTUATION",
            "UPPERCASE_SENTENCE_START",
            "WHITESPACE_RULE",
            "WORD_CONTAINS_UNDERSCORE",
        ]
        and (
            not grammar_skip_rules
            or i.ruleId not in grammar_skip_rules.split(",")
        )
    ]
    issues = [
        i for i in issues if not i.ruleId.startswith("EN_REPEATEDWORDS_")
    ]

    para_sec = None
    cur = 0
    pos = 0
    result = {"discuss": [], "comment": [], "nit": []}
    for issue in issues:
        while pos + len(review[cur + 1]) < issue.offset:
            para_sec = section_and_paragraph(
                review[cur + 1], review[cur], para_sec, is_diff=False
            )
            pos += len(review[cur])
            cur += 1

        result["nit"].append(fmt_section_and_paragraph(para_sec, "nit"))
        context = issue.context.lstrip(".")
        offset = issue.offsetInContext - (len(issue.context) - len(context))
        context = context.rstrip(".")

        compressed = re.sub(r"\s+", r" ", context[0:offset])
        offset -= len(context[0:offset]) - len(compressed)
        context = re.sub(r"\s+", r" ", context)

        if len(context) > width - 2:
            cut = math.ceil((len(context) - width + 2) / 2)
            context = context[cut:-cut]
            offset -= cut

        result["nit"].append("> " + context + "\n")
        result["nit"].append(
            "> " + " " * offset + "^" * issue.errorLength + "\n"
        )

        message = (
            issue.message.replace("“", '"')
            .replace("’s", "'s")
            .replace("n’t", "n't")
            .replace("”", '"')
            .replace("‘", '"')
            .replace("’", '"')
        )

        if not re.search(r".*[.!?]$", message):
            message += "."

        if show_rule_id:
            message = f"{message} [{issue.ruleId}]"

        result["nit"].append(wrap_para(f"{message}", width=width))

    return result
