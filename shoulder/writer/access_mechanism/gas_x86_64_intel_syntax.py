from shoulder.writer.access_mechanism.access_mechanism \
        import AccessMechanismWriter
from shoulder.logger import logger


class GasX86_64IntelSyntaxAccessMechanismWriter(AccessMechanismWriter):

    def call_readable_access_mechanism(self, outfile, reg, am, result):
        if am.name == "mov_read":
            self._call_mov_read_access_mechanism(outfile, reg, am, result)
        elif am.name == "cpuid":
            self._call_cpuid_access_mechanism(outfile, reg, am, result)
        elif am.name == "rdmsr":
            self._call_rdmsr_access_mechanism(outfile, reg, am, result)
        else:
            msg = "Access mechnism {am} is not supported"
            msg = msg.format(am=am.name)
            logger.warn(msg)

    def call_writable_access_mechanism(self, outfile, reg, am, value):
        if am.name == "mov_write":
            self._call_mov_write_access_mechanism(outfile, reg, am, value)
        elif am.name == "wrmsr":
            self._call_wrmsr_access_mechanism(outfile, reg, am, value)
        else:
            msg = "Access mechnism {am} is not supported"
            msg = msg.format(am=am.name)
            logger.warn(msg)

    def _call_mov_read_access_mechanism(self, outfile, reg, am, result):
        self._write_inline_assembly(outfile, [
                "mov %[v], " + am.source_mnemonic
            ],
            outputs='[v] "=r"(' + str(result) + ')'
        )

    def _call_cpuid_access_mechanism(self, outfile, reg, am, result):
        if reg.is_indexed:
            subleaf_mnemonic = "%[subleaf]"
            subleaf_input = '[subleaf] "r"(index)'
        else:
            subleaf_mnemonic = "0"
            subleaf_input = ""

        self._write_inline_assembly(outfile, [
                "mov eax, " + str(hex(am.leaf)),
                "mov ecx, " + subleaf_mnemonic,
                "cpuid",
                "mov %[out], " + am.output
            ],
            outputs='[out] "=r"(' + result + ')',
            inputs=subleaf_input,
            clobbers='"eax", "ebx", "ecx", "edx"'
        )

    def _call_rdmsr_access_mechanism(self, outfile, reg, am, result):
        self._write_inline_assembly(outfile, [
                "mov rcx, " + str(hex(am.address)),
                "rdmsr",
                "shl rdx, 32",
                "or rax, rdx",
                "mov %[v], rax",
            ],
            outputs='[v] "=r"(' + result + ')',
            clobbers='"rax", "rcx", "rdx"'
        )

    def _call_mov_write_access_mechanism(self, outfile, reg, am, value):
        self._write_inline_assembly(outfile, [
                "mov " + am.destination_mnemonic + ", %[v]",
            ],
            inputs='[v] "r"(' + value + ')'
        )

    def _call_wrmsr_access_mechanism(self, outfile, reg, am, value):
        self._write_inline_assembly(outfile, [
                "mov rcx, " + str(hex(am.address)),
                "mov rax, %[v]",
                "mov rdx, %[v]",
                "shr rdx, 32",
                "wrmsr",
            ],
            inputs='[v] "r"(' + value + ')',
            clobbers='"rax", "rcx", "rdx"'
        )

    def _write_inline_assembly(self, outfile, statements, outputs="", inputs="",
                              clobbers=""):
        outfile.write("__asm__ __volatile__(\n")
        for statement in statements:
            outfile.write("    \"" + str(statement) + ";\"\n")

        outfile.write("    : " + str(outputs) + "\n")
        outfile.write("    : " + str(inputs) + "\n")
        outfile.write("    : " + str(clobbers) + "\n")
        outfile.write(");")
        self.write_newline(outfile)
