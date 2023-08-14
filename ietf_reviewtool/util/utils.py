"""ietf-reviewtool utils module"""

import datetime
import ipaddress
import logging
import sys

import charset_normalizer

TEST_NET_1 = ipaddress.IPv4Network("192.0.2.0/24")
TEST_NET_2 = ipaddress.IPv4Network("198.51.100.0/24")
TEST_NET_3 = ipaddress.IPv4Network("203.0.113.0/24")
MCAST_TEST_NET = ipaddress.IPv4Network("233.252.0.0/24")
TEST_NET_V6 = ipaddress.IPv6Network("2001:db8::/32")


def die(msg: str, log: logging.Logger, err: int = 1) -> None:
    """
    Print a message and exit with an error code.

    @param      msg   The message to print
    @param      log   The log
    @param      err   The error code to return

    @return     { description_of_the_return_value }
    """
    log.error(msg)
    sys.exit(err)


def read(file_name: str, log: logging.Logger) -> str:
    """
    Read a file into a string.

    @param      file_name  The item to read
    @param      log        The log

    @return     The content of the item.
    """
    try:
        with open(file_name, "rb") as file:
            return str(charset_normalizer.from_bytes(file.read()).best())
    except FileNotFoundError as err:
        log.error("%s -> %s", file_name, err)
        return ""


def write(text: str, file_name: str) -> None:
    """
    Write a string into a file.

    @param      text       The text to write
    @param      file_name  The file name to write to

    @return     -
    """
    with open(file_name, "w", encoding="utf8") as file:
        file.write(text)


def duplicates(data: list) -> set:
    """
    Return duplicate elements in a list.

    @param      data  The list to locate duplicates in

    @return     Duplicate elements of data.
    """
    seen = {}
    dupes = set()
    for item in data:
        if item not in seen:
            seen[item] = 1
        else:
            if seen[item] == 1:
                dupes.add(item)
            seen[item] += 1
    return dupes


def get_latest(data: list, key: str) -> dict:
    """
    Gets the latest element, by timestamp in key, from data.

    @param      data  The list to return the latest element of
    @param      key   The timestamp key

    @return     The latest element by timestamp in data.
    """
    data.sort(
        key=lambda k: datetime.datetime.fromisoformat(k[key]),
        reverse=True,
    )
    return data[0]
