# Copyright (C) 2017 Jakob Kreuze, All Rights Reserved.
#
# This file is part of Hypodermic.
#
# Hypodermic is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Hypodermic is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with Hypodermic. If not, see <http://www.gnu.org/licenses/>.

"""Parsing of a program's memory mapping info from procfs."""

import collections
import re


Device = collections.namedtuple(
    "Device",
    ["major", "minor"]
)

Perms = collections.namedtuple(
    "Perms",
    ["r", "w", "x", "s"]
)

Region = collections.namedtuple(
    "Region",
    ["start", "end", "perms", "off", "dev", "inode", "path"]
)


def parse_device(line: str) -> Device:
    """Converts a device line of the form "maj:min" into a Device
       object.

    Args:
        line (str): The line to parse.

    Returns:
        The parsed Device object.
    """
    major, minor = line.split(':')
    return Device(int(major), int(minor))


def parse_perms(line: str) -> Perms:
    """Converts a permissions line of the form "rwxp" into a Perms
       object.

    Args:
        line (str): The line to parse.

    Returns:
        The parsed Perms object.
    """
    return Perms(line[0] == 'r', line[1] == 'w', line[2] == 'x', line[3] == 's')


def parse_region(line: str) -> Region:
    """Converts a line of text from the "maps" file into a Region
       object.

    Args:
        line (str): The line to parse.

    Returns:
        The parsed Region object.
    """
    ret = re.split(r"\s+", line.strip())
    if len(ret) == 6:
        address, perms, off, dev, inode, path = ret
    else:
        address, perms, off, dev, inode = ret
        path = ""
    start, end = address.split('-')
    return Region(int(start, 16), int(end, 16), parse_perms(perms),
                  int(off, 16), parse_device(dev), int(inode), path)


def maps(pid: int) -> list:
    """Gets memory mapping information for a given pid.

    Args:
        pid (int): The pid of the process to get memory mapping
            information for.

    Raises:
        TypeError: If the pid argument is not an int.
        PermissionError: If the mapping information cannot be read.

    Returns:
        A list of Region objects.
    """
    if not isinstance(pid, int):
        raise TypeError("pid argument must be an int")

    regions = []

    with open("/proc/{}/maps".format(pid)) as maps:
        for line in maps:
            regions.append(parse_region(line))

    return regions
