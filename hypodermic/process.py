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
import os.path
import re

from elftools.elf.elffile import ELFFile

from hypodermic.memory import Region, maps

AMD64_INDICES = {
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

I386_INDICES = {
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
        self._isamd64 = self._so.is_amd64
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
            Registers are tied to the host processor, not the target
            processor. For example, a 32-bit ELF will still have 64-bit
            registers on 64-bit Linux.

        Args:
            reg (str): The register to inspect. (e.g. "rax")

        Returns:
            An integer representing the value of the register.

        """
        regs = AMD64_INDICES if self._isamd64 else I386_INDICES

        if reg not in regs:
            raise ValueError("{} is not a valid register".format(reg))

        return self._getreg(self.pid, regs.get(reg))

    @property
    def arch(self) -> str:
        """Returns the architecture of the host processor.

        Note:
            The architecture of the host platform is not necessarily
            the architecture of the target executable. However, this
            value will accurately represent how registers should be
            addressed.

        Returns:
            A string representing the host processor. As of now, only
            "x64" and "x86" are supported.
        """
        return "x64" if self._isamd64 else "x86"

    @property
    def maps(self) -> list:
        """Obtain the process' memory map.

        Returns:
            A list of Region objects.
        """
        return maps(self.pid)

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
