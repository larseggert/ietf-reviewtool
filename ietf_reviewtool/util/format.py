import re

from .text import wrap_para


def fmt_section_and_paragraph(para_sec: list, cat: str) -> str:
    """
    Return a formatted prefix line indicating the current section name,
    paragraph number, and category.

    @param      para_sec  The current (paragraph number, section name) list
    @param      cat       The category to indicate

    @return     A formatted prefix line.
    """
    para_sec = para_sec if para_sec else [1, None, False]
    line = f"{para_sec[1]}, p" if para_sec[1] else "P"
    line += f"aragraph {para_sec[0]}, {cat}:\n"
    return line


def fmt_nit(changed: list, indicator: list, para_sec: list) -> list:
    """
    Format a nit.

    @param      changed    Changed lines
    @param      indicator  Indicator lines
    @param      para_sec   The current (paragraph number, section name) list

    @return     The formatted nit.
    """
    result = [fmt_section_and_paragraph(para_sec, "nit")]
    for prefix in ["-", "+"]:
        for tup in zip(changed[prefix], indicator[prefix]):
            # add the changed line followed by an indicator line
            result.append(tup[0])
            if tup[1]:
                result.append(tup[1].replace("?", prefix, 1))
        indicator[prefix].clear()
        changed[prefix].clear()
    result.append("\n")
    return result


def fmt_comment(item: dict, para_sec: list, width: int) -> list:
    """
    Format a comment.

    @param      item      The comment item dict
    @param      para_sec  The current (paragraph number, section name) list
    @param      width     The width to wrap to

    @return     The formatted comment.
    """
    result = [fmt_section_and_paragraph(para_sec, item["cat"])]
    result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
    if item["ctx"]:
        result.append("\n")
    txt = "".join([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])
    result.append(
        wrap_para(txt, width=width, end="\n\n" if item["txt"] else "")
    )
    if item["ctx"]:
        para_sec[0] -= 1  # don't count this as a paragraph
    item.clear()
    return result


def fmt_review(review: dict, width: int) -> None:
    """
    Format a review dict for datatracker submission.

    @param      review  The review to format
    @param      width   The column number to wrap the review to

    @return     Wrapped text version of the review.
    """
    boilerplate = {
        "discuss": None,
        "comment": None,
        "nit": (
            "All comments below are about very minor potential issues "
            "that you may choose to address in some way - or ignore - "
            "as you see fit. Some were flagged by automated tools (via "
            "https://github.com/larseggert/ietf-reviewtool), so there "
            "will likely be some false positives. "
            "There is no need to let me know what you did "
            "with these suggestions."
        ),
    }

    used_categories = 0
    for category in boilerplate:
        if review[category]:
            used_categories += 1

    for category in boilerplate:
        if not review[category]:
            continue

        if used_categories > 1:
            print("-" * width)
            print(category.upper())
            print("-" * width)

        if boilerplate[category]:
            print(wrap_para(boilerplate[category], width=width, end="\n"))

        for line in review[category]:
            print(line, end="")
