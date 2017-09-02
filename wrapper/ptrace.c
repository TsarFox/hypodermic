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
#include <sys/wait.h>

#include <stddef.h>
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

    while (!WIFSTOPPED(s)) {
        waitpid(pid, &s, WNOHANG);
    }

    return 0;
}


/* user_regs_struct is copied from sys/user.h so that we can debug a
   32-bit executable on a 64-bit platform. */
struct amd64_user_regs_struct {
    __extension__ unsigned long long r15;
    __extension__ unsigned long long r14;
    __extension__ unsigned long long r13;
    __extension__ unsigned long long r12;
    __extension__ unsigned long long rbp;
    __extension__ unsigned long long rbx;
    __extension__ unsigned long long r11;
    __extension__ unsigned long long r10;
    __extension__ unsigned long long r9;
    __extension__ unsigned long long r8;
    __extension__ unsigned long long rax;
    __extension__ unsigned long long rcx;
    __extension__ unsigned long long rdx;
    __extension__ unsigned long long rsi;
    __extension__ unsigned long long rdi;
    __extension__ unsigned long long orig_rax;
    __extension__ unsigned long long rip;
    __extension__ unsigned long long cs;
    __extension__ unsigned long long eflags;
    __extension__ unsigned long long rsp;
    __extension__ unsigned long long ss;
    __extension__ unsigned long long fs_base;
    __extension__ unsigned long long gs_base;
    __extension__ unsigned long long ds;
    __extension__ unsigned long long es;
    __extension__ unsigned long long fs;
    __extension__ unsigned long long gs;
};


struct i386_user_regs_struct {
    unsigned long ebx;
    unsigned long ecx;
    unsigned long edx;
    unsigned long esi;
    unsigned long edi;
    unsigned long ebp;
    unsigned long eax;
    unsigned long xds;
    unsigned long xes;
    unsigned long xfs;
    unsigned long xgs;
    unsigned long orig_eax;
    unsigned long eip;
    unsigned long xcs;
    unsigned long eflags;
    unsigned long esp;
    unsigned long xss;
};


unsigned long long getreg64(int pid, int idx) {
    struct amd64_user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return ((unsigned long long *) &regs)[idx];
}


unsigned long getreg32(int pid, int idx) {
    struct i386_user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    return ((unsigned long  *) &regs)[idx];
}
