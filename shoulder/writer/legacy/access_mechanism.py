from typing import TextIO
from shoulder.model.register import Register
from shoulder.model.access_mechanism import AbstractAccessMechanism
from shoulder.writer.formating import write_indent
from shoulder.writer.c.variable import declare_variable
from shoulder.writer.c.variable import return_variable
from shoulder.writer.gcc.inline_assembly import write_inline_assembly
from shoulder.logger import logger


def call_readable_access_mechanism(outfile: TextIO, reg: Register,
        am: AbstractAccessMechanism, indent: int=0):
    write_indent(outfile, indent)

    #  if am.name == "mov_read":
    #      _call_mov_read_access_mechanism(outfile, reg, am)
    if am.name == "cpuid":
        _call_cpuid_access_mechanism(outfile, reg, am)
    elif am.name == "rdmsr":
        _call_rdmsr_access_mechanism(outfile, reg, am)
    else:
        msg = "Access mechnism {am} is not supported for inline GCC assembler"
        msg = msg.format(am=am.name)
        logger.error(msg)


def call_writable_access_mechanism(outfile: TextIO, reg: Register,
         am: AbstractAccessMechanism, value: str, indent: int=0):
    write_indent(outfile, indent)

    if am.name == "mov_write":
        _call_mov_write_access_mechanism(outfile, reg, am, value)
    elif am.name == "wrmsr":
        _call_wrmsr_access_mechanism(outfile, reg, am, value)
    else:
        msg = "Access mechnism {am} is not supported for inline GCC assembler"
        msg = msg.format(am=am.name)
        logger.error(msg)


def _call_mov_read_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)

    write_inline_assembly(outfile,
        [
            "mov %[v], " + am.source_mnemonic
        ],
        outputs='[v] "=r"(' + var + ')'
    )

    return_variable(outfile, var)


def _call_cpuid_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)

    if reg.is_indexed:
        subleaf_mnemonic = "%[subleaf]"
        subleaf_input = '[subleaf] "r"(index)'
    else:
        subleaf_mnemonic = "0"
        subleaf_input = ""

    write_inline_assembly(outfile,
        [
            "mov eax, " + str(hex(am.leaf)),
            "mov ecx, " + subleaf_mnemonic,
            "cpuid",
            "mov %[out], " + am.output
        ],
        outputs='[out] "=r"(' + var + ')',
        inputs=subleaf_input,
        clobbers='"eax", "ebx", "ecx", "edx"'
    )


def _call_rdmsr_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)

    write_inline_assembly(outfile,
        [
            "mov rcx, " + str(hex(am.address)),
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            "mov %[v], rax",
        ],
        outputs='[v] "=r"(' + var + ')',
        clobbers='"rax", "rcx", "rdx"'
    )

    return_variable(outfile, var)


def _call_mov_write_access_mechanism(outfile, reg, am, value):
    write_inline_assembly(outfile,
        [
            "mov " + am.destination_mnemonic + ", %[v]",
        ],
        inputs='[v] "r"(' + value + ')'
    )


def _call_wrmsr_access_mechanism(outfile, reg, am, value):
    write_inline_assembly(outfile,
        [
            "mov rcx, " + str(hex(am.address)),
            "mov rax, %[v]",
            "mov rdx, %[v]",
            "shr rdx, 32",
            "wrmsr",
        ],
        inputs='[v] "r"(' + value + ')',
        clobbers='"rax", "rcx", "rdx"'
    )
