import os
import textwrap

from shoulder.generator.abstract_generator import AbstractGenerator
from shoulder.logger import logger
from shoulder.config import config
from shoulder.exception import ShoulderGeneratorException
from shoulder.filter import filters
from shoulder.transform import transforms
#  import shoulder.gadget


class YamlDataGenerator(AbstractGenerator):
    def generate(self, regs, outpath):
        try:
            aarch64_regs = filters["aarch64"].filter_inclusive(regs)
            aarch32_regs = filters["aarch32"].filter_inclusive(regs)
            external_regs = filters["external"].filter_inclusive(regs)

            sub_outpath = os.path.abspath(os.path.join(outpath, "aarch64"))
            if not os.path.exists(sub_outpath):
                os.makedirs(sub_outpath)

            for reg in aarch64_regs:
                outfile = reg.name.lower() + ".yml"
                outfile_path = os.path.abspath(os.path.join(sub_outpath, outfile))
                with open(outfile_path, "w") as outfile:
                    self._generate(outfile, reg)

            sub_outpath = os.path.abspath(os.path.join(outpath, "aarch32"))
            if not os.path.exists(sub_outpath):
                os.makedirs(sub_outpath)

            for reg in aarch32_regs:
                outfile = reg.name.lower() + ".yml"
                outfile_path = os.path.abspath(os.path.join(sub_outpath, outfile))
                with open(outfile_path, "w") as outfile:
                    self._generate(outfile, reg)

            sub_outpath = os.path.abspath(os.path.join(outpath, "external"))
            if not os.path.exists(sub_outpath):
                os.makedirs(sub_outpath)

            for reg in external_regs:
                outfile = reg.name.lower() + ".yml"
                outfile_path = os.path.abspath(os.path.join(sub_outpath, outfile))
                with open(outfile_path, "w") as outfile:
                    self._generate(outfile, reg)

        except Exception as e:
            msg = "{g} failed to generate output {out}: {exception}".format(
                g=str(type(self).__name__),
                out=outpath,
                exception=e)
            raise ShoulderGeneratorException(msg)

    def _generate(self, outfile, reg):
        self._generate_register_attributes(outfile, reg)
        self._generate_register_access_mechanisms(outfile, reg)
        self._generate_register_fieldsets(outfile, reg)

    def _generate_register_attributes(self, outfile, reg):
        outfile.write("- name: " + str(reg.name) + "\n")
        outfile.write("  long_name: \"" + str(reg.long_name) + "\"\n")

        outfile.write("  purpose: |\n")
        outfile.write("       \"\n")
        wrapped = textwrap.wrap(str(reg.purpose), width=72)
        for line in wrapped:
            line = "       " + str(line) + "\n"
            outfile.write(line)
        outfile.write("       \"\n")

        outfile.write("  size: " + str(reg.size) + "\n")
        outfile.write("  arch: " + str(reg.arch) + "\n")
        outfile.write("  execution_state: " + str(reg.execution_state) + "\n")

        if reg.is_internal:
            outfile.write("  is_internal: True\n")

        if reg.is_optional:
            outfile.write("  is_optional: True\n")

        if reg.is_banked:
            outfile.write("  is_banked: True\n")

        outfile.write("\n")

    def _generate_register_access_mechanisms(self, outfile, reg):
        outfile.write("  access_mechanisms:\n")
        for am_name, am_list in reg.access_mechanisms.items():
            for am in am_list:
                outfile.write("      - name: " + str(am.name) + "\n")

                if am.is_read():
                    outfile.write("        is_read: True\n")

                if am.is_write():
                    outfile.write("        is_write: True\n")

                if am.name == "ldr" or am.name == "str":
                    outfile.write("        component: " + str(am.component) + "\n")
                    outfile.write("        offset: " + str(hex(am.offset)) + "\n")

                if am.name == "mcr" or am.name == "mrc":
                    outfile.write("        coproc: " + str(hex(am.coproc)) + "\n")
                    outfile.write("        opc1: " + str(hex(am.opc1)) + "\n")
                    outfile.write("        opc2: " + str(hex(am.opc2)) + "\n")
                    outfile.write("        crm: " + str(hex(am.crm)) + "\n")
                    outfile.write("        crn: " + str(hex(am.crn)) + "\n")

                if am.name == "mcrr" or am.name == "mrrc":
                    outfile.write("        coproc: " + str(hex(am.coproc)) + "\n")
                    outfile.write("        opc1: " + str(hex(am.opc1)) + "\n")
                    outfile.write("        crm: " + str(hex(am.crm)) + "\n")

                if am.name == "mrs_banked" or am.name == "msr_banked":
                    outfile.write("        m: " + str(hex(am.m)) + "\n")
                    outfile.write("        r: " + str(hex(am.r)) + "\n")
                    outfile.write("        m1: " + str(hex(am.m1)) + "\n")

                if am.name == "msr_register" or am.name == "mrs_register":
                    outfile.write("        op0: " + str(hex(am.op0)) + "\n")
                    outfile.write("        op1: " + str(hex(am.op1)) + "\n")
                    outfile.write("        op2: " + str(hex(am.op2)) + "\n")
                    outfile.write("        crm: " + str(hex(am.crm)) + "\n")
                    outfile.write("        crn: " + str(hex(am.crn)) + "\n")
                    outfile.write("        operand_mnemonic: " + str(am.operand_mnemonic) + "\n")

                if am.name == "vmsr" or am.name == "vmrs":
                    outfile.write("        reg: " + str(am.reg) + "\n")
                    outfile.write("        operand_mnemonic: " + str(am.operand_mnemonic) + "\n")

                outfile.write("\n")

    def _generate_register_fieldsets(self, outfile, reg):
        outfile.write("  fieldsets:\n")
        for idx, fs in enumerate(reg.fieldsets):
            if fs.name:
                outfile.write("      - name: " + str(fs.name) + "\n")
            else:
                outfile.write("      - name: " + "fieldset_" + str(idx + 1) + "\n")

            if fs.condition:
                outfile.write("        condition: \"" + str(fs.condition) + "\"\n")

            if fs.size:
                outfile.write("        size: " + str(fs.size) + "\n")

            outfile.write("\n")

            self._generate_fields(outfile, reg, fs)

            if idx != len(reg.fieldsets) - 1:
                outfile.write("\n")

    def _generate_fields(self, outfile, reg, fs):
        fs.fields.reverse()
        for idx, f in enumerate(fs.fields):
            outfile.write("          - name: " + str(f.name) + "\n")

            if f.long_name:
                outfile.write("            long_name: \"" + str(f.long_name) + "\"\n")

            outfile.write("            lsb: " + str(f.lsb) + "\n")
            outfile.write("            msb: " + str(f.msb) + "\n")

            if f.readable:
                outfile.write("            readable: True\n")

            if f.writable:
                outfile.write("            writable: True\n")

            if f.lockable:
                outfile.write("            lockable: True\n")

            if f.write_once:
                outfile.write("            write_once: True\n")

            if f.write_1_clear:
                outfile.write("            write_1_clear: True\n")

            if f.name == "0":
                outfile.write("            reserved0: True\n")

            if f.name == "1":
                outfile.write("            reserved1: True\n")

            if idx != len(fs.fields) - 1:
                outfile.write("\n")
