/* An self-contained example of a program that maps the glibc RTLD into
   its own address space using open(2) and mmap(2).

   Sizes and offsets are hardcoded to avoid any complicated ELF parsing.

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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* This is going to vary from distro to distro. */
#define LD_LINUX_PATH "/lib64/ld-2.25.so"

/* Copied from Linux fs/binfmt_elf.c */
#define ELFEXEC_PAGESIZE 4096 /* TODO: Set this to the system pagesize. */
#define ELF_MIN_ALIGN ELFEXEC_PAGESIZE

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

/* Pre-computed. Mirrors total_mapping_size in fs/binfmt_elf.c */
#define INIT_MAP_SIZE \
    ELF_PAGEALIGN(0x00223bc0 + 0x00001538 - ELF_PAGESTART(0x00000000))

#define AFTER_MAP_SIZE \
    ELF_PAGEALIGN(0x00000000000013b8 + ELF_PAGEOFFSET(0x0000000000001538))
#define AFTER_MAP_OFF \
    ELF_PAGEALIGN(0x0000000000023bc0 - ELF_PAGEOFFSET(0x0000000000001538))


int main(void) {
    int   fd;
    char  buf;
    void *ld_initial;
    void *ld_after;
    void *ld_bss;

    if ((fd = open(LD_LINUX_PATH, O_RDONLY)) < 0) {
        fprintf(stderr, "Failed to open the runtime linker\n");
        return 1;
    }

    if ((ld_initial = mmap(NULL, INIT_MAP_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        fprintf(stderr, "Failed to map the runtime linker's .text\n");
        return 1;
    }

    if ((ld_after = mmap((void *) ELF_PAGESTART((unsigned long) ld_initial + 0x0223bc0), AFTER_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, AFTER_MAP_OFF)) == MAP_FAILED) {
        fprintf(stderr, "Failed to map the runtime linker's .data\n");
        return 1;
    }

    printf("Mapping successful!\n");
    printf("You can check procfs maps to see actual permissions.\n");
    printf("%s .text:   %p\n", LD_LINUX_PATH, ld_initial);
    printf("%s .data:   %p\n", LD_LINUX_PATH, ld_after);

    printf("Press any key to continue...\n");
    read(0, &buf, 1);

    munmap(ld_initial, INIT_MAP_SIZE);
    munmap(ld_after, AFTER_MAP_SIZE);
    close(fd);

    return 0;
}
