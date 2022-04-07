"""ietf-reviewtool grammr module"""

import math
import re

import language_tool_python  # type: ignore

from .review import IetfReview
from .util.docposition import DocPosition
from .util.text import unfold


def check_grammar(
    text: str,
    grammar_skip_rules: str,
    review: IetfReview,
    show_rule_id: bool = False,
) -> None:
    """
    Check document grammar.

    @param      text                The document text
    @param      grammar_skip_rules  The grammar rules to skip
    @param      review              The IETF review to comment upon
    @param      show_rule_id        Whether to show rule names in messages

    @return     { description_of_the_return_value }
    """
    issues = [
        i
        for i in language_tool_python.LanguageTool("en-US").check(unfold("".join(text)))
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
        and (not grammar_skip_rules or i.ruleId not in grammar_skip_rules.split(","))
    ]
    issues = [i for i in issues if not i.ruleId.startswith("EN_REPEATEDWORDS_")]

    doc_pos = DocPosition()
    cur = 0
    pos = 0
    for issue in issues:
        while pos + len(text[cur + 1]) < issue.offset:
            doc_pos.update(text[cur + 1], text[cur], is_diff=False)
            pos += len(text[cur])
            cur += 1

        review.nit(doc_pos.fmt_section_and_paragraph("nit"), end="")
        context = issue.context.lstrip(".")
        offset = issue.offsetInContext - (len(issue.context) - len(context))
        context = context.rstrip(".")

        compressed = re.sub(r"\s+", r" ", context[0:offset])
        offset -= len(context[0:offset]) - len(compressed)
        context = re.sub(r"\s+", r" ", context)

        if len(context) > review.width - 2:
            cut = math.ceil((len(context) - review.width + 2) / 2)
            context = context[cut:-cut]
            offset -= cut

        review.nit("> " + context, wrap=False, end="")
        review.nit("> " + " " * offset + "^" * issue.errorLength, wrap=False, end="")

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

        review.nit(message)
