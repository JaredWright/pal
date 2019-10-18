from typing import TextIO
from shoulder.model.access_mechanism import AbstractAccessMechanism
from shoulder.writer.formating import write_indent
from shoulder.logger import logger


def call_readable_access_mechanism(outfile: TextIO, am: AbstractAccessMechanism,
                                   indent: int=0):
    write_indent(outfile, indent)

    if am.name == "mov_read":
        _call_mov_read_access_mechanism(outfile, am)
    elif am.name == "cpuid":
        _call_cpuid_access_mechanism(outfile, am)
    elif am.name == "rdmsr":
        _call_rdmsr_access_mechanism(outfile, am)
    else:
        msg = "Access mechnism {am} is not supported in C++"
        msg = msg.format(am=am.name)
        logger.error(msg)


def call_writable_access_mechanism(outfile: TextIO, am: AbstractAccessMechanism,
                                   value: str, indent: int=0):
    write_indent(outfile, indent)

    if am.name == "mov_write":
        _call_mov_write_access_mechanism(outfile, am, value)


def _call_mov_read_access_mechanism(outfile, am):
    accessor = "SHOULDER_MOV_READ_IMPL({src})".format(
        src=am.source_mnemonic
    )

    outfile.write(accessor)


def _call_cpuid_access_mechanism(outfile, am):
    accessor = "SHOULDER_CPUID_IMPL({leaf}, {subleaf})".format(
        leaf=am.leaf,
        subleaf=am.subleaf
    )

    outfile.write(accessor)


def _call_aarch64_encoded_read_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH64_ENCODED_READ_IMPL({encoding})".format(
        encoding=hex(am.binary_encoded())
    )
    outfile.write(accessor)


def _call_mrs_register_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH64_MRS_REGISTER_IMPL({mnemonic})".format(
        mnemonic=am.operand_mnemonic.lower()
    )
    outfile.write(accessor)


def _call_mrs_banked_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH32_MRS_BANKED_IMPL({mnemonic})".format(
        mnemonic=am.operand_mnemonic.lower()
    )
    outfile.write(accessor)


def _call_mrc_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH32_MRC_IMPL({coproc}, {opc1}, {crn}, {crm}, {opc2})"
    accessor = accessor.format(
        coproc=am.coproc,
        opc1=am.opc1,
        crn=am.crn,
        crm=am.crm,
        opc2=am.opc2
    )

    outfile.write(accessor)


def _call_mrrc_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH32_MRRC_IMPL({coproc}, {opc1}, {crm})"
    accessor = accessor.format(
        coproc=am.coproc,
        opc1=am.opc1,
        crm=am.crm
    )

    outfile.write(accessor)


def _call_vmrs_access_mechanism(outfile, am):
    accessor = "SHOULDER_AARCH32_VMRS_IMPL({key})".format(
        key=am.operand_mnemonic.lower()
    )
    outfile.write(accessor)


def _call_ldr_access_mechanism(outfile, am):
    null_return = "0xffffffff"
    if reg.size == 64:
        null_return = "0xffffffffffffffff"

    accessor =  "if ({base} == 0x0) return {null_ret};\n"
    accessor += "return *(({ret_size} *)({base} + {reg}::offset));\n"
    accessor = accessor.format(
        base=str(am.component) + "_base",
        null_ret=null_return,
        ret_size=self._register_size_type(reg),
        reg=reg.name.lower()
    )
    outfile.write(accessor)


def _call_mov_write_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_MOV_WRITE_IMPL({dest}, {val})".format(
        dest=am.destination_mnemonic,
        val=str(value)
    )

    outfile.write(accessor)


def _call_aarch64_encoded_write_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH64_ENCODED_WRITE_IMPL({encoding})".format(
        encoding=hex(am.binary_encoded())
    )
    outfile.write(accessor)


def _call_msr_register_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH64_MSR_REGISTER_IMPL({mnemonic}, {val})".format(
        mnemonic=am.operand_mnemonic.lower(),
        val=str(value)
    )
    outfile.write(accessor)


def _call_mcr_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH32_MCR_IMPL({coproc}, {opc1}, {crn}, {crm}, {opc2}, {val})"
    accessor = accessor.format(
        coproc=am.coproc,
        opc1=am.opc1,
        crn=am.crn,
        crm=am.crm,
        opc2=am.opc2,
        val=str(value)
    )

    outfile.write(accessor)


def _call_mcrr_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH32_MCRR_IMPL({coproc}, {opc1}, {crm}, {val})"
    accessor = accessor.format(
        coproc=am.coproc,
        opc1=am.opc1,
        crm=am.crm,
        val=str(value)
    )

    outfile.write(accessor)


def _call_msr_banked_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH32_MSR_BANKED_IMPL({mnemonic}, {val})".format(
        mnemonic=am.operand_mnemonic.lower(),
        val=str(value)
    )

    outfile.write(accessor)


def _call_vmsr_access_mechanism(outfile, am, value):
    accessor = "SHOULDER_AARCH32_VMSR_IMPL({key}, {val})".format(
        key=am.operand_mnemonic.lower(),
        val=str(value)
    )
    outfile.write(accessor)


def _call_str_access_mechanism(outfile, am, value):
    null_return = "0xffffffff"
    if reg.size == 64:
        null_return = "0xffffffffffffffff"

    accessor =  "if ({base} == 0x0) return {null_ret};\n"
    accessor += "*(({ret_size} *)({base} + {reg}::offset)) = {val};\n"
    accessor = accessor.format(
        base=str(am.component) + "_base",
        null_ret=null_return,
        ret_size=self._register_size_type(reg),
        reg=reg.name.lower(),
        val=str(value)
    )
    outfile.write(accessor)
