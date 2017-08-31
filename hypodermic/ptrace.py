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

from hypodermic.memory import Region, maps


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

    def detach(self):
        """Explicitly detaches from the process.

        Raises:
            OSError: If the process cannot be detached from.
        """
        if not self._is_parent and self._detach(ctypes.c_int(self.pid)):
            raise OSError("Could not detach from pid {}".format(self.pid))

    def cont(self):
        """Continues until the program is haulted.

        Raises:
            OSError: If the process cannot be continued.
        """
        if self._cont(ctypes.c_int(self.pid)):
            raise OSError("Could not continue")

    @property
    def maps(self) -> list:
        """Obtain the process' memory map.

        Returns:
            A list of Region objects.
        """
        return maps(self.pid)

    # FIXME: This approach does not work outside of seeing if the
    # process has an RTLD page. The reality is that the RTLD is
    # broken up into independent several pages.
    @property
    def rtld(self) -> Region:
        """Obtain the region of memory for the process' RTLD, if it
           exists.

        Returns:
            The Region object belonging to the RTLD, or None if no
            RTLD was found.
        """
        for region in self.maps:
            if re.search(r"ld.+\.so", region.path):
                return region
