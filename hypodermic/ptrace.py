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

"""Wrapper for the ptrace system call, since python-ptrace sucks."""

import ctypes


# TODO: Instantiate from binary path, as well.
class Process(object):
    """Process attached via ptrace.

    Note:
        The process is implicitly detached from upon destruction of this
        object.

    Args:
        pid (:obj:`int`, optional): The pid of the process to attach to.
            Defaults to 0, which means that it will not be used.
        path (:obj:`str`, optional): The path of the binary to run.
            Defaults to "", which will be used if no pid is specified.

    Raises:
        TypeError: If the pid argument is not an int.
        OSError: If the pid cannot be attached to.
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
        # FIXME: How are we going to deal with the path?
        self._so = ctypes.cdll.LoadLibrary("/tmp/libptracew.so")
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
