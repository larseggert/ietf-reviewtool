"""ietf-reviewtool grammar module"""

import math
import re
import requests_cache

import language_tool_python  # type: ignore

from .review import IetfReview
from .util.docposition import DocPosition
from .util.text import unfold, wrap_para
from .util.fetch import fetch_init_cache

# Target chunk size for LanguageTool to avoid server heap space errors.
# Chunks may exceed this if no paragraph break is found.
TARGET_CHUNK_SIZE = 40000


def _check_text_chunked(lt: language_tool_python.LanguageTool, full_text: str) -> list:
    """
    Check text for grammar issues, chunking at paragraph boundaries.

    Splits large texts at paragraph boundaries (double newlines) to stay under
    LanguageTool's size limits while preserving correct offset positions.
    Chunks may exceed TARGET_CHUNK_SIZE if no paragraph break is found.

    @param      lt         The LanguageTool instance
    @param      full_text  The complete text to check

    @return     List of grammar issues with offsets relative to full_text
    """
    if len(full_text) <= TARGET_CHUNK_SIZE:
        return list(lt.check(full_text))

    issues = []
    chunk_start = 0

    while chunk_start < len(full_text):
        # Find the next paragraph break after TARGET_CHUNK_SIZE.
        search_start = chunk_start + TARGET_CHUNK_SIZE
        if search_start >= len(full_text):
            chunk_end = len(full_text)
        else:
            next_para = full_text.find("\n\n", search_start)
            if next_para == -1:
                chunk_end = len(full_text)
            else:
                chunk_end = next_para + 2

        chunk = full_text[chunk_start:chunk_end]
        chunk_issues = lt.check(chunk)

        # Adjust offsets to be relative to the full text.
        for issue in chunk_issues:
            issue.offset += chunk_start
        issues.extend(chunk_issues)

        chunk_start = chunk_end

    return issues


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

    full_text = unfold("".join(text))
    issues = [
        i
        for i in _check_text_chunked(lt, full_text)
        if i.rule_id
        not in [
            "HYPHEN_TO_EN",
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
        and (not grammar_skip_rules or i.rule_id not in grammar_skip_rules.split(","))
    ]
    issues = [i for i in issues if not i.rule_id.startswith("EN_REPEATEDWORDS_")]

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
        offset = issue.offset_in_context - (len(issue.context) - len(context))
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
        nit += f"{quote}{' ' * offset}{'^' * issue.error_length}\n"
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
            message = f"{message} [{issue.rule_id}]"

        review.nit("Grammar/style", nit + wrap_para(message, "\n", width), wrap=False)
