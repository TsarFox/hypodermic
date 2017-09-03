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

from hypodermic.process import Process


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
        alert("Creating process at path '{}'...".format(args.create))
        p = Process(path=args.create)

        shellcode = b"\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc7\x01\x00" + \
                    b"\x00\x00\x48\xc7\xc2\x29\x00\x00\x00\x48\x8d\x35" + \
                    b"\x00\x00\x00\x00\x48\x81\xc6\x0d\x00\x00\x00\x0f" + \
                    b"\x05\x90\x90\x90\xcc\x61\x6d\x64\x36\x34\x20\x4c" + \
                    b"\x69\x6e\x75\x78\x20\x73\x79\x73\x5f\x77\x72\x69" + \
                    b"\x74\x65\x20\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65" + \
                    b"\x20\x62\x79\x20\x4a\x61\x6b\x6f\x62\x0a"

        old_rip = p.get_register("rip")
        alert("%rip at {}".format(hex(old_rip)))
        old_code = p.read_bytes(old_rip, len(shellcode))
        p.write_bytes(old_rip, shellcode)
        while p.read_bytes(p.get_register("rip"), 1) != b'\xcc':
            p.single_step()
        alert("Hit breakpoint!")
        p.write_bytes(old_rip, old_code)
        p.set_register("rip", old_rip)
        alert("%rip reset to {}".format(hex(p.get_register("rip"))))
        p.continue_until_haulted()
    else:
        alert("Attaching to process with pid {}...".format(args.attach))
        p = Process(pid=args.attach)
