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

"""Module for generating payloads."""

from keystone import *


def assemble(code: str, arch="amd64", syntax="att") -> bytes:
    """Assembles the given assembly code.

    Args:
        code (str): The code to assemble
        arch (:obj:`str`, optional): The target architecture.
            Defaults to "amd64"
        syntax (:obj:`str`, optional): The assembly syntax to use.
            Defaults to "att"

    Returns:
        A `bytes` object containing the resultant machine code.
    """
    wordlen = KS_MODE_64 if arch == "amd64" else KS_MODE_32
    ks = Ks(KS_ARCH_X86, wordlen)
    if syntax == "att":
        ks.syntax = keystone.KS_OPT_SYNTAX_ATT
    encoded, _ = ks.asm(code)
    return bytes(encoded)


# FIXME: Relative addressing is untested in i386.
def open_shellcode(path: str, flags=0, arch="amd64") -> bytes:
    """Generates shellcode to open a file descriptor.

    Args:
        path (str): The path of the file to open.
        flags (:obj:`int`, optional): Flags to pass to open. Defaults to
            O_RDONLY.
        arch (:obj:`str`, optional): The target architecture.
            Defaults to "amd64".

    Returns:
        The assembled shellcode, as a `bytes` object.
    """
    if arch == "amd64":
        asm = "        jmp __path_end;" \
              "__path:" \
              "        .asciz \"{}\";" \
              "__path_end:" \
              "        movq $0x02,       %rax;" \
              "        leaq (%rip),      %rdi;" \
              "        subq $. - __path, %rdi;" \
              "        movq ${},         %rsi;" \
              "        movq $0x00,       %rdx;" \
              "        syscall;".format(path, flags)
    else:
        asm = "        jmp __path_end;" \
              "__path:" \
              "        .asciz \"{}\";" \
              "__path_end:" \
              "        movl $0x05,   %eax;" \
              "        call $. + 5;" \
              "        popl %ebx;" \
              "        subl $. - 4 - __path, %ebx;"
              "        movl ${},     %ecx;" \
              "        movl $0x00,   %edx;" \
              "        int $0x80;".format(path, flags)
    return assemble(asm, arch)
