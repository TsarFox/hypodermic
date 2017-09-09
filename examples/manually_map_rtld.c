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


int main(void) {
    int   fd;
    char  buf;
    void *ld_text;
    void *ld_rodata;
    void *ld_data;

    if ((fd = open(LD_LINUX_PATH, O_RDONLY)) < 0) {
        fprintf(stderr, "Failed to open the runtime linker\n");
        return 1;
    }

    if ((ld_text = mmap(NULL, 0x23000, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        fprintf(stderr, "Failed to map the runtime linker's .text\n");
        return 1;
    }

    if ((ld_rodata = mmap(ld_text + 0x223000, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0x23000)) == MAP_FAILED) {
        fprintf(stderr, "Failed to map the runtime linker's .rodata\n");
        return 1;
    }

    if ((ld_data = mmap(ld_text + 0x224000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0x24000)) == MAP_FAILED) {
        fprintf(stderr, "Failed to map the runtime linker .data\n");
        return 1;
    }

    printf("Mapping successful!\n");
    printf("You can check procfs maps to see actual permissions.\n");
    printf("%s .text:   %p\n", LD_LINUX_PATH, ld_text);
    printf("%s .rodata: %p\n", LD_LINUX_PATH, ld_rodata);
    printf("%s .data:   %p\n", LD_LINUX_PATH, ld_data);

    printf("Press any key to continue...\n");
    read(0, &buf, 1);

    munmap(ld_data, 0x23000);
    munmap(ld_rodata, 0x1000);
    munmap(ld_text, 0x1000);
    close(fd);

    return 0;
}
