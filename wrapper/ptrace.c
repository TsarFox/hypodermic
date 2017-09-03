/* ptrace.c - Wrappers for the ptrace system call.

   Copyright (C) 2017 Jakob Kreuze, All Rights Reserved.

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
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <stddef.h>
#include <string.h>
#include <unistd.h>


static void run_target(const char *path) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        return;
    }

    execl(path, path, 0);
}


int new_proc(const char *path) {
    int   wait_stat;
    pid_t pid;

    if (path == NULL) {
        return -1;
    }

    pid = fork();

    if (pid == 0) {
        run_target(path);
    } else if (pid > 0) {
        wait(&wait_stat);
    } else {
        return -1;
    }

    return pid;
}


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

    waitpid(pid, &s, WNOHANG);
    return 0;
}


int step(int pid) {
    int s;

    if ((ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) < 0) {
        return -1;
    }

    while (!WIFSTOPPED(s)) {
        waitpid(pid, &s, WNOHANG);
    }

    return 0;
}


/* TODO: As of now, Hypodermis is strongly tied to the Intel x86
   family of processors. This should really be expanded. */
int is_amd64(void) {
    struct utsname ub;

    uname(&ub);

    return !strcmp(ub.machine, "x86_64");
}


#ifdef __x86_64__
unsigned long long getreg(int pid, int idx) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return ((unsigned long long *) &regs)[idx];
}

void setreg(int pid, int idx, unsigned long long value) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    ((unsigned long long *) &regs)[idx] = value;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}
#else
unsigned long getreg(int pid, int idx) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return ((unsigned long *) &regs)[idx];
}

void setreg(int pid, int idx, unsigned long value) {
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    ((unsigned long *) &regs)[idx] = value;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}
#endif
