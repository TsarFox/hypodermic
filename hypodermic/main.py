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

"""Command-line interface to Hypodermic."""

import argparse
import sys
import textwrap

from hypodermic.ptrace import Process


class CustomHelp(argparse.HelpFormatter):
    """Modifications to argparse's default HelpFormatter."""
    def _fill_text(self, text, width, indent):
        filled = []
        for line in text.splitlines(keepends=True):
            filled.append(indent + line)
        return "".join(filled)

    def _split_lines(self, text, width):
        return text.splitlines()

    def add_usage(self, usage, actions, groups, prefix=None):
        prefix = prefix or "Usage: "
        both = super(CustomHelp, self)
        return both.add_usage(usage, actions, groups, prefix)


def _alert(quiet: bool):
    def alert(*args):
        if not quiet:
            print(*args)
    return alert


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=CustomHelp,
        usage="%(prog)s [-a pid] [-c path] [options]",
        description="Don't share needles, brah!"
    )
    parser._positionals.title = "Positional Arguments"
    parser._optionals.title = "Optional Arguments"

    parser.add_argument(
        "target",
        help="The target shared object to inject."
    )
    parser.add_argument(
        "-q",
        "--quiet",
        help="Suppress everything but critical output"
    )

    doc = parser.add_argument_group("Documentation")
    doc.add_argument(
        "-h",
        "--help",
        action="help",
        help="Display this help page and exit."
    )
    doc.add_argument(
        "-V",
        "--version",
        action="version",
        version="What version?",
        help="Display the currently installed version and exit."
    )

    proc = parser.add_argument_group("Process Manipulation")
    meth = proc.add_mutually_exclusive_group()
    proc.add_argument(
        "-a",
        "--attach",
        metavar="PID",
        help="The pid of a process to attach to."
    )
    proc.add_argument(
        "-c",
        "--create",
        metavar="BIN",
        help="The path of a binary to execute and attach to."
    )

    args = parser.parse_args()
    alert = _alert(args.quiet)

    if args.attach is None and args.create is None:
        print("No action specified. Quitting!")
        sys.exit(1)

    if args.create:
        alert("Creating process at path {}".format(args.create))
        p = Process(path=args.create)
    else:
        alert("Attaching to process with pid {}".format(args.attach))
        p = Process(pid=args.attach)
