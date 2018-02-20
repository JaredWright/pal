#
# Shoulder
# Copyright (C) 2018 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from shoulder.generator.abstract_generator import AbstractGenerator
from shoulder.logger import logger
from shoulder.config import config

class CxxHeaderGenerator(AbstractGenerator):
    def generator_id():
        return "c++ header-only generator"

    def generate(self, objects, outpath):
        logger.info("Generating C++ header: " + str(outpath))
        with open(outpath, "w") as outfile:
            self._write_license(outfile)
            self._write_external_includes(outfile)
            self._write_include_guard_open(outfile)
            self._write_namespace_open(outfile)

            for obj in objects:
                self._write_object(obj, outfile)

            self._write_namespace_close(outfile)
            self._write_include_guard_close(outfile)

    def _write_license(self, outfile):
        logger.debug("Writing license from: " + str(config.license_template_path))
        with open(config.license_template_path, "r") as license:
            for line in license:
                outfile.write("// " + line)
        outfile.write("\n")

    def _write_external_includes(self, outfile):
        outfile.write("#include \"" + config.regs_h_path + "\"\n")
        outfile.write("\n")

    def _write_include_guard_open(self, outfile):
        outfile.write("#ifndef SHOULDER_AARCH64_H\n")
        outfile.write("#define SHOULDER_AARCH64_H\n")
        outfile.write("\n")

    def _write_include_guard_close(self, outfile):
        outfile.write("#endif\n\n")

    def _write_namespace_open(self, outfile):
        namespaces = config.cxx_namespace.split("::")
        for namespace in namespaces:
            outfile.write("namespace " + namespace + "\n{\n")
        outfile.write("\n")

    def _write_namespace_close(self, outfile):
        namespaces = config.cxx_namespace.split("::")
        for namespace in namespaces:
            outfile.write("}\n")
        outfile.write("\n")

    def _write_object(self, obj, outfile):
        logger.debug("Writing output object:\n" + str(obj))
        self._write_register(obj, outfile)

    def _write_register(self, reg, outfile):
        # Comment and namespace
        regname = reg.name.lower()
        outfile.write("// " + reg.long_name + "\n")
        outfile.write("// " + reg.purpose + "\n")
        outfile.write("namespace " + regname + "\n{\n")

        # Getter
        outfile.write("\tinline ")
        outfile.write("uint64_t " if reg.size == 64 else "uint32_t ")
        outfile.write(config.register_read_function)
        outfile.write("(void) noexcept { ")
        outfile.write("GET_SYSREG_FUNC(" + regname + ") }\n")

        # Setter
        outfile.write("\tinline void ")
        outfile.write(config.register_write_function + "(")
        outfile.write("uint64_t " if reg.size == 64 else "uint32_t ")
        outfile.write("val) noexcept { ")
        outfile.write("SET_SYSREG_BY_VALUE_FUNC(" + regname + ", val) }")

        # Fieldsets
        self._write_register_fieldsets(reg, outfile)

        outfile.write("\n}\n\n")

    def _write_register_fieldsets(self, reg, outfile):
        logger.info("Writing register fieldsets")

    def _write_register_bitfield(self, reg, outfile):
        logger.info("Writing register bitfield")

    def _write_register_field(self, reg, outfile):
        logger.info("Writing register field")
