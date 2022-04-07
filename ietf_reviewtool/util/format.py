"""ietf-reviewtool format module"""

import re

from .docposition import DocPosition


def fmt_nit(
    changed: dict[str, list[str]], indicator: dict[str, list[str]], doc_pos: DocPosition
) -> str:
    """
    Format a nit.

    @param      changed    Changed lines
    @param      indicator  Indicator lines
    @param      doc_pos    The current document position

    @return     The formatted nit.
    """
    result = [doc_pos.fmt_section_and_paragraph("nit")]
    for prefix in ["-", "+"]:
        for tup in zip(changed[prefix], indicator[prefix]):
            # add the changed line followed by an indicator line
            result.append(tup[0])
            if tup[1]:
                result.append(tup[1].replace("?", prefix, 1))
        indicator[prefix].clear()
        changed[prefix].clear()
    return "".join(result)


def fmt_comment(item: dict, doc_pos: DocPosition) -> str:
    """
    Format a comment.

    @param      item     The comment item dict
    @param      doc_pos  The current document position

    @return     The formatted comment.
    """
    result = [doc_pos.fmt_section_and_paragraph(item["cat"])]
    result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
    if item["ctx"]:
        result.append("\n")
    txt = "".join([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])

    result.append(txt)
    if item["ctx"]:
        doc_pos.para_num -= 1  # don't count this as a paragraph
    item.clear()
    return "".join(result)
