"""ietf-reviewtool agenda module"""

import json
import logging
from typing import Any, cast

from .util.fetch import fetch_url


def get_current_agenda(datatracker: str, log: logging.Logger) -> dict:
    """
    Download and the current IESG telechat agenda in JSON format.

    @param      datatracker  The datatracker URL to use
    @param      log          The log

    @return     The current agenda as a dict.
    """
    agenda = fetch_url(datatracker + "/iesg/agenda/agenda.json", log, use_cache=False)
    if not agenda:
        return {}
    return cast(dict[Any, Any], json.loads(agenda))


def get_items_on_agenda(agenda: dict) -> list:
    """
    Given an IESG telechat agenda dict, return the list of items that are on it.

    @param      agenda  An agenda dict

    @return     A list of the items on the given agenda.
    """
    return [
        doc["docname"] + ("-" + doc["rev"] if "rev" in doc else "")
        for _, sec in agenda.get("sections", {}).items()
        for doc_type in ["docs", "wgs"]
        for doc in sec.get(doc_type, [])
    ]
