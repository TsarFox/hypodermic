import pytest

from hypodermic.process import Process
from hypodermic.shellcode import assemble

# The program to be tested. Not necessarily important, the binary just
# has to exist.
PROCNAME = "/bin/ls"


@pytest.fixture
def process():
    return Process(path=PROCNAME)


# Asserts that instructions can be written at the instruction pointer.
def test_process_memio(process):
    if process.arch == "x64":
        ip = process.get_register("rip")
        backup = process.read_bytes(ip, 0x10)
        assert len(backup) == 0x10

        assert process.write_bytes(ip, b'\x90' * 0x10) == 0x10
        assert process.read_bytes(ip, 0x10) == b'\x90' * 0x10

        assert process.write_bytes(ip, backup) == 0x10
    else:
        ip = process.get_register("eip")
        backup = process.read_bytes(ip, 0x10)
        assert len(backup) == 0x10

        assert process.write_bytes(ip, b'\x90' * 0x10) == 0x10
        assert process.read_bytes(ip, 0x10) == b'\x90' * 0x10

        assert process.write_bytes(ip, backup) == 0x10


# Asserts that writes to the extended %ax register are persistent.
def test_process_registers(process):
    if process.arch == "x64":
        rax = process.get_register("rax")
        process.set_register("rax", 0xdeadbeef)
        assert process.get_register("rax") == 0xdeadbeef
        process.set_register("rax", rax)
        assert process.get_register("rax") == rax
    else:
        eax = process.get_register("eax")
        process.set_register("eax", 0xdeadbeef)
        assert process.get_register("eax") == 0xdeadbeef
        process.set_register("eax", eax)
        assert process.get_register("eax") == eax


# Asserts that code can be run and that its effects are persistent.
def test_run_code(process):
    if process.arch == "x64":
        code = assemble("movq $0xdeadbeef, %rax;")
        rax = process.get_register("rax")
        process.run_code(code, preserve=["rax"])
        assert process.get_register("rax") == 0xdeadbeef
        process.set_register("rax", rax)
    else:
        code = assemble("movl $0xdeadbeef, %eax;")
        eax = process.get_register("eax")
        process.run_code(code, preserve=["eax"])
        assert process.get_register("eax") == 0xdeadbeef
        process.set_register("eax", eax)
