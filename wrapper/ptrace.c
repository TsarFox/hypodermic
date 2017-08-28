/* Copyright (C) 2017 Jakob Kreuze, All Rights Reserved.

   This file is part of Hypodermic.

   Hypodermic is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at
   your option) any later version.

   Hypodermic is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Hypodermic. If not, see <http://www.gnu.org/licenses/>. */

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <stddef.h>


int attach(int pid) {
    if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);
    return 0;
}


int detach(int pid) {
    return ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0;
}


int cont(int pid) {
    int s;

    if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0) {
        return -1;
    }

    while (!WIFSTOPPED(s)) {
        waitpid(pid, &s, WNOHANG);
    }

    return 0;
}
