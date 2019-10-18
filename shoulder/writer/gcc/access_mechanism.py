from typing import TextIO
from shoulder.model.register import Register
from shoulder.model.access_mechanism import AbstractAccessMechanism
from shoulder.writer.formating import write_indent
from shoulder.writer.c.variable import declare_variable
from shoulder.writer.c.variable import return_variable
from shoulder.logger import logger


def call_readable_access_mechanism(outfile: TextIO, reg: Register,
        am: AbstractAccessMechanism, indent: int=0):
    write_indent(outfile, indent)

    if am.name == "mov_read":
        _call_mov_read_access_mechanism(outfile, reg, am)
    elif am.name == "cpuid":
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


def _start_inline_assembly_statement(outfile):
    outfile.write("__asm__ __volatile__(\n")

def _end_inline_assembly_statement(outfile):
    outfile.write(");\n")

def _call_mov_read_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)
    _start_inline_assembly_statement(outfile)
    outfile.write("    \"mov %[v], " + am.source_mnemonic + "\\n\"\n")
    outfile.write("    : [v] \"=r\"(val)\n")
    _end_inline_assembly_statement(outfile)
    return_variable(outfile, var)


def _call_cpuid_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)
    _start_inline_assembly_statement(outfile)
    outfile.write("    \"mov eax, " + str(hex(am.leaf)) + "\\n\"\n")
    if reg.is_indexed:
        outfile.write("    \"mov ecx, %[subleaf]\\n\"\n")
    else:
        outfile.write("    \"mov ecx, 0\\n\"\n")
    outfile.write("    \"cpuid\\n\"\n")
    outfile.write("    \"mov %[out], " + am.output  + "\\n\"\n")
    outfile.write("    : [out] \"=r\"(" + var + ")\n")
    if reg.is_indexed:
        outfile.write("    : [subleaf] \"r\"(index)\n")
    else:
        outfile.write("    : \n")
    outfile.write("    : \"eax\", \"ebx\", \"ecx\", \"edx\"\n")
    _end_inline_assembly_statement(outfile)
    return_variable(outfile, var)


def _call_rdmsr_access_mechanism(outfile, reg, am):
    var = declare_variable(outfile, "result", reg.size)
    _start_inline_assembly_statement(outfile)
    outfile.write("    \"rdmsr %[v], " + str(hex(am.address)) + "\\n\"\n")
    outfile.write("    : [v] \"=r\"(val)\n")
    _end_inline_assembly_statement(outfile)
    return_variable(outfile, var)


def _call_mov_write_access_mechanism(outfile, reg, am, value):
    _start_inline_assembly_statement(outfile)
    outfile.write("    \"mov " + am.destination_mnemonic + ", %[v]\\n\"\n")
    outfile.write("    :\n")
    outfile.write("    : [v] \"r\"(val)\n")
    _end_inline_assembly_statement(outfile)


def _call_wrmsr_access_mechanism(outfile, reg, am, value):
    _start_inline_assembly_statement(outfile)
    outfile.write("    \"wrmsr %[v], " + str(hex(am.address)) + "\\n\"\n")
    outfile.write("    :\n")
    outfile.write("    : [v] \"r\"(val)\n")
    _end_inline_assembly_statement(outfile)


