"""ietf-reviewtool format module"""

import re

from .docposition import DocPosition


def fmt_heading(doc_pos: DocPosition, mkd_heading_level: int):
    """
    Return a heading generated for the indicated document position

    @param      doc_pos            The document position
    @param      mkd_heading_level  If >0, generates a Markdown heading at the indicated
                                   level

    @return     The heading
    """
    heading = doc_pos.fmt_section_and_paragraph()
    if mkd_heading_level > 0:
        heading = f"{'#' * mkd_heading_level} {heading}"
    return heading


def fmt_nit(
    changed: dict[str, list[str]],
    indicator: dict[str, list[str]],
    doc_pos: DocPosition,
    mkd_heading_level: int,
) -> str:
    """
    Format a nit.

    @param      changed            Changed lines
    @param      indicator          Indicator lines
    @param      doc_pos            The current document position
    @param      mkd_heading_level  If >0, generates Markdown with a heading of the
                                   indicated level

    @return     The formatted nit.
    """
    result = [fmt_heading(doc_pos, mkd_heading_level)]
    if mkd_heading_level > 0:
        result.append("```\n")
    for prefix in ["-", "+"]:
        for tup in zip(changed[prefix], indicator[prefix]):
            # add the changed line followed by an indicator line
            result.append(tup[0])
            if tup[1]:
                result.append(tup[1].replace("?", prefix, 1))
        indicator[prefix].clear()
        changed[prefix].clear()
    if mkd_heading_level > 0:
        result.append("```\n")
    return "".join(result)


def fmt_comment(item: dict, doc_pos: DocPosition, mkd_heading_level: int) -> str:
    """
    Format a comment.

    @param      item               The comment item dict
    @param      doc_pos            The current document position
    @param      mkd_heading_level  If >0, generates Markdown with a heading of the
                                   indicated level

    @return     The formatted comment.
    """
    result = [fmt_heading(doc_pos, mkd_heading_level)]

    if item["ctx"]:
        # strip empty lines at beginning and end
        for index in [-1, 0]:
            while re.search(r"^\s*$", item["ctx"][index]) is not None:
                item["ctx"].pop(index)

        if mkd_heading_level > 0:
            result.append("```\n")
            result.extend(item["ctx"])
        else:
            result.extend([re.sub(r".(.*)", r">\1", x) for x in item["ctx"]])
            if item["ctx"]:
                result.append("\n")
        if mkd_heading_level > 0:
            result.append("```")

    result.append("\n")
    txt = "".join([re.sub(r". (.*)", r"\1", x) for x in item["txt"]])

    result.append(txt)
    if item["ctx"]:
        doc_pos.para_num -= 1  # don't count the comment paragraph
    item.clear()
    return "".join(result)
