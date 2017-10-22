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
              "        subl $. - 4 - __path, %ebx;" \
              "        movl ${},     %ecx;" \
              "        movl $0x00,   %edx;" \
              "        int $0x80;".format(path, flags)
    return assemble(asm, arch)


def close_shellcode(fd: int, arch="amd64") -> bytes:
    """Generates shellcode to close a file descriptor.

    Args:
        fd (int): The file descriptor to close.
        arch (:obj:`str`, optional): The target architecture.
            Defaults to "amd64".

    Returns:
        The assembled shellcode, as a `bytes` object.
    """
    if arch == "amd64":
        asm = "        movq $0x03, %rax;" \
              "        movq ${},   %rdi;" \
              "        syscall;".format(fd)
    else:
        asm = "        movq $0x06, %eax;" \
              "        movq ${},   %ebx;" \
              "        int $0x80;;".format(fd)
    return assemble(asm, arch)


# FIXME: Syscall number may be incorrect for i386.
def mmap_shellcode(addr=0, size=0, prot=0, flags=0, fd=-1, off=0, arch="amd64"):
    """Generates shellcode to map a region of memory.

    Args:
        addr (:obj:`int`, optional): The address, or 0 if unimportant.
        size (:obj:`int`, optional): The desired size of the mapping.
        prot (:obj:`int`, optional): The protections for the mapping.
        flags (:obj:`int`, optional): Any other flags for the mapping.
        fd (:obj:`int`, optional): A file descriptor to map.
        off (:obj:`int`, optional): An offset in the file descriptor.
        arch (:obj:`str`, optional): The target architecture.

    Returns:
        The assembled shellcode, as a `bytes` object.
    """
    if arch == "amd64":
        asm = "        movq $0x09, %rax;" \
              "        movq ${},   %rdi;" \
              "        movq ${},   %rsi;" \
              "        movq ${},   %rdx;" \
              "        movq ${},   %r10;" \
              "        movq ${},   %r8;" \
              "        movq ${},   %r9;" \
              "        syscall;".format(addr, size, prot, flags, fd, off)
    else:
        asm = "        movl $0x5a, %eax;" \
              "        movl ${},   %ebx;" \
              "        movl ${},   %ecx;" \
              "        movl ${},   %edx;" \
              "        movl ${},   %esi;" \
              "        movl ${},   %edi;" \
              "        movl ${},   %ebp;" \
              "        int $0x80;".format(addr, size, prot, flags, fd, off)
    return assemble(asm, arch)


def munmap_shellcode(addr=0, size=0, arch="amd64"):
    """Generates shellcode to map a region of memory.

    Args:
        addr (:obj:`int`, optional): The address of the mapping.
        size (:obj:`int`, optional): The size of the mapping.
        arch (:obj:`str`, optional): The target architecture.

    Returns:
        The assembled shellcode, as a `bytes` object.
    """
    if arch == "amd64":
        asm = "        movq $0x0b, %rax;" \
              "        movq ${},   %rdi;" \
              "        movq ${},   %rsi;" \
              "        syscall;".format(addr, size)
    else:
        asm = "        movl $0x5b, %eax;" \
              "        movl ${},   %ebx;" \
              "        movl ${},   %ecx;" \
              "        int $0x80;".format(addr, size)
    return assemble(asm, arch)


# TODO: i386 not implemented.
def dlopen_shellcode(dlopen: int, ret: int, path: str, arch="amd64"):
    """Generates shellcode to invoke _dl_open in the RTLD.

    Args:
        dlopen (int): The absolute address of _dl_open.
        path (str): The path of the library to open.

    Returns:
        The assembled shellcode, as a `bytes` object.
    """
    if arch == "amd64":
        asm = "        jmp __path_end;" \
              "__path:" \
              "        .asciz \"{}\";" \
              "__path_end:" \
              "        leaq (%rip),              %rdi;" \
              "        subq $. - __path,         %rdi;" \
              "        movq $0x80000101,         %rsi;" \
              "        movq ${},                 %rdx;" \
              "        movq $0xfffffffffffffffe, %rcx;" \
              "        movq $0x00,               %r8;" \
              "        movq $0x00,               %r9;" \
              "        movq $0x00,               %r10;" \
              "        callq ${};".format(path, ret, dlopen)
    else:
        asm = ""
    return assemble(asm, arch)
