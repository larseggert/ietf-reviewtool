"""ietf-reviewtool format module"""

import re


def fmt_section_and_paragraph(para_sec: list, cat: str) -> str:
    """
    Return a formatted prefix line indicating the current section name,
    paragraph number, and category.

    @param      para_sec  The current (paragraph number, section name) list
    @param      cat       The category to indicate

    @return     A formatted prefix line.
    """
    para_sec = para_sec if para_sec else [1, None, False]
    line = f"{para_sec[1].strip()}, p" if para_sec[1] else "P"
    line += f"aragraph {para_sec[0]}, {cat}:\n"
    return line


def fmt_nit(changed: list, indicator: list, para_sec: list) -> str:
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
    return "".join(result)


def fmt_comment(item: dict, para_sec: list) -> str:
    """
    Format a comment.

    @param      item      The comment item dict
    @param      para_sec  The current (paragraph number, section name) list

    @return     The formatted comment.
    """
    result = [fmt_section_and_paragraph(para_sec, item["cat"])]
    result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
    if item["ctx"]:
        result.append("\n")
    txt = "".join([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])

    result.append(txt)
    if item["ctx"]:
        para_sec[0] -= 1  # don't count this as a paragraph
    item.clear()
    return "".join(result)
