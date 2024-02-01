"""ietf-reviewtool grammr module"""

import math
import re
import requests_cache

import language_tool_python  # type: ignore

from .review import IetfReview
from .util.docposition import DocPosition
from .util.text import unfold, wrap_para
from .util.fetch import fetch_init_cache


def check_grammar(
    text: list,
    grammar_skip_rules: str,
    review: IetfReview,
    width: int,
    show_rule_id: bool = False,
) -> None:
    """
    Check document grammar.

    @param      text                The document text (as lines)
    @param      grammar_skip_rules  The grammar rules to skip
    @param      review              The IETF review to comment upon
    @param      show_rule_id        Whether to show rule names in messages

    @return     { description_of_the_return_value }
    """
    # the languagetool auto-download seems to fail if the cache is enabled
    requests_cache.uninstall_cache()
    lt = language_tool_python.LanguageTool("en-US")
    fetch_init_cache()

    issues = [
        i
        for i in lt.check(unfold("".join(text)))
        if i.ruleId
        not in [
            "ADVERTISEMENT_OF_FOR",
            "ALL_OF_THE",
            "ARROWS",
            "BOTH_AS_WELL_AS",
            "COMMA_COMPOUND_SENTENCE",
            "COMMA_COMPOUND_SENTENCE_2",
            "COMMA_PARENTHESIS_WHITESPACE",
            "COPYRIGHT",
            "CURRENCY",
            "DASH_RULE",
            "DATE_FUTURE_VERB_PAST",
            "DATE_NEW_YEAR",
            "DIFFERENT_THAN",
            "DOUBLE_PUNCTUATION",
            "EN_COMPOUNDS",
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
            "OUTSIDE_OF",
            "PLUS_MINUS",
            "POSSESSIVE_APOSTROPHE",
            "PUNCTUATION_PARAGRAPH_END",
            "R_SYMBOL",
            "RETURN_IN_THE",
            "SENTENCE_WHITESPACE",
            "SO_AS_TO",
            "SOME_OF_THE",
            "TRADEMARK",
            "UNIT_SPACE",
            "UNLIKELY_OPENING_PUNCTUATION",
            "UPPERCASE_SENTENCE_START",
            "WHETHER",
            "WHITESPACE_RULE",
            "WITH_THE_EXCEPTION_OF",
            "WORD_CONTAINS_UNDERSCORE",
        ]
        and (not grammar_skip_rules or i.ruleId not in grammar_skip_rules.split(","))
    ]
    issues = [i for i in issues if not i.ruleId.startswith("EN_REPEATEDWORDS_")]

    doc_pos = DocPosition()
    cur = 0
    pos = 0
    for issue in issues:
        while pos + len(text[cur]) <= issue.offset:
            doc_pos.update(text[cur + 1], text[cur], is_diff=False)
            pos += len(text[cur])
            cur += 1

        nit = doc_pos.fmt_section_and_paragraph()
        if review.mkd:
            nit = f"#### {nit}"
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

        quote = "> "
        if review.mkd:
            nit += "```\n"
            quote = ""
        nit += f"{quote}{context}\n"
        nit += f"{quote}{' ' * offset}{'^' * issue.errorLength}\n"
        if review.mkd:
            nit += "```\n"

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

        review.nit("Grammar/style", nit + wrap_para(message, "\n", width), wrap=False)
