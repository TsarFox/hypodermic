# Hypodermic

The ability to inject a shared library into a program is generally very
desirable, allowing a researcher to execute code from the address space of
another process. The preferred method of performing this on Linux, specifying
environment variables such as `LD_PRELOAD`, requires that the dynamic linker is
present and supports it. In a majority of cases, this will work perfectly
fine. In fact, this method is extremely powerful and any calls a binary makes to
a library will be directed to the injected shared object. However, there are
cases in which one would want to merely inject code to be run from a debugger,
not caring about whether or not library calls made by the binary are
redirected. There have been a few attempts at this in the past, such as
[linux-inject][1], which makes use of the `__libc_dlopen_mode` routine in glibc.
This is oftentimes unsuccessful, being very dependent upon how glibc was
compiled.

The point of Hypodermic is to find a means of injecting a dynamic library into
any Linux executable, even ones that are statically-linked, and transferring
this method over to [PINCE][2] when it is stable enough. The current goal is the
ability to inject an internal cheat into Counter-Strike: Global Offensive, such
as [AimTux][3]. This will signal that the method has reached a point of
viability.

Hypodermic is free software, licensed under the [GNU General Public License.][4]


## Current Attempts

The initial, honestly quite naïve, attempt at implementing this was to inject
code that would map the entire shared object into the address space of the
inferior process, and only parsing the ELF data to get the offsets of library
routines. This did not work, as the process of loading an ELF library into
memory is far more complicated than calling mmap(2) on the file.

The second iteration also involves injecting code into the inferior process, but
instead maps the Linux runtime linker into memory, if it is not already there,
and utilizes the internal _dl_open routine. This is difficult, as it means
mapping it the way the kernel would to ensure proper initialization of the RTLD.


## Important Resources

* [Understanding Linux ELF RTLD internals][5]
* [Runtime Process Infection][6]
* [ELF Program Header][7]
* [Dynamic Loader Operation][8]
* [About ELF Auxiliary Vectors][9]
* [Code Injection into Running Linux Application][10]
* [Special Sections][11]


[1]: https://github.com/gaffe23/linux-inject
[2]: https://github.com/korcankaraokcu/PINCE
[3]: https://github.com/AimTuxOfficial/AimTux/
[4]: https://www.gnu.org/licenses/gpl.html
[5]: http://s.eresi-project.org/inc/articles/elf-rtld.txt
[6]: http://phrack.org/issues/59/8.html
[7]: http://www.sco.com/developers/gabi/latest/ch5.pheader.html
[8]: https://sourceware.org/glibc/wiki/DynamicLoader
[9]: http://articles.manugarg.com/aboutelfauxiliaryvectors
[10]: https://www.codeproject.com/Articles/33340/Code-Injection-into-Running-Linux-Application
[11]: http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/specialsections.html
