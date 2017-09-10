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

"""ctypes wrapper for ptrace."""

import ctypes
import os
import re

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from hypodermic.memory import Region, maps
from hypodermic.shellcode import (assemble, close_shellcode, dlopen_shellcode,
                                  mmap_shellcode, munmap_shellcode,
                                  open_shellcode)

_AMD64_INDICES = {
    "r15": 0,
    "r14": 1,
    "r13": 2,
    "r12": 3,
    "rbp": 4,
    "rbx": 5,
    "r11": 6,
    "r10": 7,
    "r9": 8,
    "r8": 9,
    "rax": 10,
    "rcx": 11,
    "rdx": 12,
    "rsi": 13,
    "rdi": 14,
    "orig_rax": 15,
    "rip": 16,
    "cs": 17,
    "eflags": 18,
    "rsp": 19,
    "ss": 20,
    "fs_base": 21,
    "gs_base": 22,
    "ds": 23,
    "es": 24,
    "fs": 25,
    "gs": 26
}

_AMD64_REGS = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]

_I386_INDICES = {
    "ebx": 0,
    "ecx": 1,
    "edx": 2,
    "esi": 3,
    "edi": 4,
    "ebp": 5,
    "eax": 6,
    "xds": 7,
    "xes": 8,
    "xfs": 9,
    "xgs": 10,
    "orig_eax": 11,
    "eip": 12,
    "xcs": 13,
    "eflags": 14,
    "esp": 15,
    "xss": 16
}

_I386_REGS = [
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
]


class Process(object):
    """Process attached via ptrace.

    Note:
        The process is implicitly detached from upon destruction of this
        object, if appropriate.

    Args:
        pid (:obj:`int`, optional): The pid of the process to attach to.
            Defaults to 0, which means that the argument will not be
            used.
        path (:obj:`str`, optional): The path of the binary to run.
            Defaults to "", which will as the target if a pid is not
            specified, either.

    Raises:
        TypeError: If the pid argument is not an int, or if the path
            argument is not a string.
        OSError: If the pid cannot be attached to, if the process could
            not be created for the given binary, or if any wrapper
            libraries could not be loaded.
    """

    def __init__(self, pid=0, path=""):
        if not isinstance(pid, int):
            raise TypeError("pid argument must be an int")
        elif not isinstance(path, str):
            raise TypeError("path argument must be a string")
        self._load_ffi_methods()

        if pid != 0:
            self._is_parent = False
            if self._attach(ctypes.c_int(pid)):
                raise OSError("Could not attach to pid {}".format(pid))
        else:
            self._is_parent = True
            self.pid = self._new_proc(ctypes.c_char_p(path.encode()))
            if self.pid < 0:
                raise OSError("Could not create process {}".format(path))

    def __del__(self):
        if hasattr(self, "_is_parent") and not self._is_parent:
            self.detach()

    def _load_ffi_methods(self):
        # setuptools/cython hack.
        script_path = os.path.abspath(os.path.dirname(__file__))

        for filename in os.listdir(os.path.join(script_path, "..")):
            if filename.startswith("libhypodermicw"):
                lib_path = os.path.join(script_path, "..", filename)
                break
        else:
            raise OSError("Could not find wrapper library.")

        self._so = ctypes.cdll.LoadLibrary(lib_path)
        self._new_proc = self._so.new_proc
        self._attach = self._so.attach
        self._detach = self._so.detach
        self._cont = self._so.cont
        self._step = self._so.step
        self._isamd64 = self._so.is_amd64
        self._setreg = self._so.setreg
        self._getreg = self._so.getreg
        self._getreg.restype = ctypes.c_ulonglong

    def detach(self):
        """Explicitly detaches from the process.

        Raises:
            OSError: If the process cannot be detached from.
        """
        if not self._is_parent and self._detach(ctypes.c_int(self.pid)):
            raise OSError("Could not detach from pid {}".format(self.pid))

    def continue_until_haulted(self):
        """Continues until the program is haulted.

        Raises:
            OSError: If the process cannot be continued.
        """
        if self._cont(ctypes.c_int(self.pid)):
            raise OSError("Could not continue")

    def single_step(self):
        """Execute a single instruction.

        Raises:
            OSError: If the process cannot be put into single step mode.
        """
        if self._step(ctypes.c_int(self.pid)):
            raise OSError("Could not continue")

    def write_bytes(self, address: int, src: bytes) -> int:
        """Writes data into process memory.

        Args:
            address (int): The address at which to write the bytes.
            src (:obj:`bytes`): The bytes to write.

        Raises:
            ValueError: If the address does not exist in the process
                address space.

        Returns:
            The number of bytes written.
        """
        for region in self.maps:
            if address >= region.start and address + len(src) < region.end:
                break
        else:
            raise ValueError("address was not in the process address space")

        with open("/proc/{}/mem".format(self.pid), "wb") as mem:
            mem.seek(address)
            return mem.write(src)

    def read_bytes(self, address: int, n: int) -> bytes:
        """Reads data from process memory.

        Args:
            address (int): The address at which to read from.
            n (int): The number of bytes to read.

        Raises:
            ValueError: If the address does not exist in the process
                address space.

        Returns:
            A `bytes` object containing the bytes read.
        """
        for region in self.maps:
            if address >= region.start and address + n < region.end:
                break
        else:
            raise ValueError("address was not in the process address space")

        with open("/proc/{}/mem".format(self.pid), "rb") as mem:
            mem.seek(address)
            return mem.read(n)

    def get_register(self, reg: str) -> int:
        """Returns the value of the given register.

        Note:
            Registers names are tied to the host processor, not the
            target processor. For example, a 32-bit ELF will still have
            64-bit registers on 64-bit Linux. It would be wise to query
            the `arch` property of the Process object.

        Args:
            reg (str): The register to inspect. (e.g. "rax")

        Returns:
            An integer representing the value of the register.
        """
        regs = _AMD64_INDICES if self._isamd64 else _I386_INDICES

        if reg not in regs:
            raise ValueError("{} is not a valid register".format(reg))

        return self._getreg(self.pid, regs.get(reg))

    def set_register(self, reg: str, val: int):
        """Sets the value of the given register.

        Note:
            Registers names are tied to the host processor, not the
            target processor. For example, a 32-bit ELF will still have
            64-bit registers on 64-bit Linux. It would be wise to query
            the `arch` property of the Process object.

        Args:
            reg (str): The register to modify. (e.g. "rax")
            val (int): The new value for the register.
        """
        regs = _AMD64_INDICES if self._isamd64 else _I386_INDICES

        if reg not in regs:
            raise ValueError("{} is not a valid register".format(reg))

        if self._isamd64:
            return self._setreg(self.pid, regs.get(reg), ctypes.c_ulonglong(val))
        return self._setreg(self.pid, regs.get(reg), ctypes.c_ulong(val))

    def _run_code_32(self, code: bytes, preserve: list):
        reg_order = [reg for reg in _I386_REGS if reg not in preserve]
        push = assemble("".join("pushl %{};".format(reg) for reg in reg_order), "i386")
        pop = assemble("".join("popl %{};".format(reg) for reg in reversed(reg_order)), "i386")
        bp = assemble("nop; nop; int3;", "i386")
        payload = push + code + pop + bp

        old_eip = self.get_register("eip")
        old_code = self.read_bytes(old_eip, len(payload))
        self.write_bytes(old_eip, payload)
        while self.read_bytes(self.get_register("eip"), 1) != b"\xcc":
            self.single_step()
        self.write_bytes(old_eip, old_code)
        self.set_register("eip", old_eip)

    def _run_code_64(self, code: bytes, preserve: list):
        reg_order = [reg for reg in _AMD64_REGS if reg not in preserve]
        push = assemble("".join("pushq %{};".format(reg) for reg in reg_order))
        pop = assemble("".join("popq %{};".format(reg) for reg in reversed(reg_order)))
        bp = assemble("nop; nop; int3;")
        payload = push + code + pop + bp

        old_rip = self.get_register("rip")
        old_code = self.read_bytes(old_rip, len(payload))
        self.write_bytes(old_rip, payload)
        while self.read_bytes(self.get_register("rip"), 1) != b"\xcc":
            self.single_step()
        self.write_bytes(old_rip, old_code)
        self.set_register("rip", old_rip)

    def run_code(self, code: bytes, preserve=[]) -> tuple:
        """Executes code on the inferior.

        Args:
            code (:obj:`bytes`): The code to execute.
            preserve (:obj:`list`, optional): Registers that should be
                allowed to be clobbered.

        Returns:
            A pair of lists, the first containing the values of
            preserved registers before the code was executed, and the
            second containing the values of preserved registers after
            the code was executed.
        """
        before = [self.get_register(reg) for reg in preserve]
        if self.arch == "x64":
            self._run_code_64(code, preserve)
        else:
            self._run_code_32(code, preserve)
        after = [self.get_register(reg) for reg in preserve]
        return before, after

    def open(self, path: str) -> int:
        """Attempts to open a file descriptor within the inferior.

        Args:
            path (str): The path of the file to open.

        Raises:
            OSError: If the path cannot be opened.

        Returns:
            The file descriptor.
        """
        if self.arch == "x64":
            old_rax = self.get_register("rax")
            self.run_code(open_shellcode(path), preserve=["rax"])
            fd = self.get_register("rax")
            self.set_register("rax", old_rax)
        else:
            old_eax = self.get_register("eax")
            self.run_code(open_shellcode(path, arch="i386"), preserve=["eax"])
            fd = self.get_register("eax")
            self.set_register("eax", old_eax)

        # FIXME: fd is parsed as a ctypes.c_ulonglong...
        if fd < 0:
            raise OSError("Couldn't open {}".format(path))
        return fd

    def close(self, fd: int):
        """Attempts to close a file descriptor within the inferior.

        Args:
            fd (int): The file descriptor to close.
        """
        if self.arch == "x64":
            self.run_code(close_shellcode(fd))
        else:
            self.run_code(close_shellcode(fd, arch="i386"))

    def mmap(self, addr=0, size=0, prot=0, flags=0, fd=-1, off=0) -> int:
        """Introduce a new mapping to the process' address space.

        Args:
            addr (:obj:`int`, optional): The address, or 0 if
                unimportant.
            size (:obj:`int`, optional): The desired size of the
                mapping.
            prot (:obj:`int`, optional): The protections for the
                mapping.
            flags (:obj:`int`, optional): Any other flags for the
                mapping.
            fd (:obj:`int`, optional): A file descriptor to map.
            off (:obj:`int`, optional): An offset in the file
                descriptor.

        Raises:
            OSError: If the mapping cannot be made.

        Returns:
            The address the mapping was made at.
        """
        if self.arch == "x64":
            old_rax = self.get_register("rax")
            self.run_code(mmap_shellcode(addr, size, prot, flags, fd, off, path),
                          preserve=["rax"])
            res = self.get_register("rax")
            self.set_register("rax", old_rax)
        else:
            old_eax = self.get_register("eax")
            self.run_code(mmap_shellcode(addr, size, prot, flags, fd, off, path,
                                         arch="i386"), preserve=["eax"])
            res = self.get_register("eax")
            self.set_register("eax", old_eax)

        # FIXME: fd is parsed as a ctypes.c_ulonglong...
        if res == -1:
            raise OSError("Couldn't complete mapping.")
        return res

    def munmap(self, addr=0, size=0):
        """Removes a mapping from the process' address space.

        Args:
            addr (:obj:`int`, optional): The address, or 0 if
                unimportant.
            size (:obj:`int`, optional): The desired size of the
                mapping.
        Raises:
            OSError: If the mapping cannot be made.

        Returns:
            The address the mapping was made at.
        """
        if self.arch == "x64":
            self.run_code(munmap_shellcode(addr, size))
        else:
            self.run_code(munmap_shellcode(addr, size, arch="i386"))

    def dlopen(self, path: str) -> int:
        """Maps a shared object into the process address space.

        Args:
            path (str): The path of the shared object to inject.

        Raises:
            OSError: If the process does not have a usable RTLD.

        Returns:
            The address at which the library was loaded.
        """
        if not self.rtld:
            raise OSError("Process does not have a usable RTLD")

        if self.arch == "x64":
            old_rax = self.get_register("rax")
            self.run_code(dlopen_shellcode(self.rtld_dl_open_addr, path),
                          preserve=["rax"])
            addr = self.get_register("rax")
            self.set_register("rax", old_rax)
        else:
            old_eax = self.get_register("eax")
            self.run_code(dlopen_shellcode(self.rtld_dl_open_addr, path,
                                           arch="i386"), preserve=["eax"])
            addr = self.get_register("eax")
            self.set_register("eax", old_eax)
        return addr

    def page_start(self, addr: int) -> int:
        return addr & ~(self.page_size - 1)

    def page_offset(self, addr: int) -> int:
        return addr & (self.page_size - 1)

    def page_align(self, addr: int) -> int:
        return (addr + self.page_size - 1) & ~(self.page_size - 1)

    # FIXME: Not tested on i386.
    @property
    def page_size(self) -> int:
        return 4096

    @property
    def arch(self) -> str:
        """Returns the architecture of the host processor.

        Note:
            The architecture of the host platform is not necessarily
            the architecture of the target executable. However, this
            value will accurately represent which registers are
            available.

        Returns:
            A string representing the host processor. As of now, only
            "x64" and "x86" are supported.
        """
        return "x64" if self._isamd64 else "x86"

    @property
    def rtld_dl_open_addr(self) -> int:
        """Obtain the absolute address of _dl_open in main memory.

        Raises:
            OSError: If either the process has no instance of the RTLD,
                or the RTLD lacks sufficient symbols.

        Returns:
            An integer containing the address.
        """
        if self.rtld is None:
            raise OSError("Process has no RTLD instance")

        with open(self.rtld.path, "rb") as rtld:
            elf = ELFFile(rtld)
            symtab = elf.get_section_by_name(".symtab")

            if not isinstance(symtab, SymbolTableSection):
                raise OSError("RTLD has no usable symbol table")

            res = symtab.get_symbol_by_name("_dl_open")
            if len(res) < 1:
                raise OSError("RTLD has no _dl_open symbol")
            return self.rtld.start + res[0].entry.st_value

    @property
    def maps(self) -> list:
        """Obtain the process' memory map.

        Returns:
            A list of Region objects.
        """
        return maps(self.pid)

    # TODO: Return something more detailed than the list of open fds.
    @property
    def fds(self) -> list:
        """Obtain currently open file descriptors for the process.

        Returns:
            A list of integer file descriptors.
        """
        return [int(fd) for fd in os.listdir("/proc/{}/fd/".format(self.pid))]

    @property
    def rtld(self) -> Region:
        """Obtain the base region of memory for the process' RTLD, if it
           exists.

        Returns:
            The Region object belonging to the RTLD, or None if no
            RTLD was found.
        """
        for region in self.maps:
            if re.search(r"ld.+\.so", region.path) and region.off == 0:
                return region
