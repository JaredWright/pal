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

import os

import shoulder.gadget
from shoulder.generator.abstract_generator import AbstractGenerator
#  from shoulder.logger import logger
from shoulder.config import config
from shoulder.filter import filters
from shoulder.transform import transforms
from shoulder.exception import ShoulderGeneratorException
from shoulder.writer.writer_factory import make_writer


class CxxBaseGenerator(AbstractGenerator):
    def __init__(self):
        self.writer = make_writer(
            "c++11",
            "gas_x86_64_intel_syntax",
            "printf_utf8",
            "unix"
        )

    def setup_registers(self, regs):
        pass
        #  regs = filters["intel_x64"].filter_inclusive(regs)
        regs = filters["no_access_mechanism"].filter_exclusive(regs)
        regs = transforms["remove_reserved_0"].transform(regs)
        regs = transforms["remove_reserved_1"].transform(regs)
        regs = transforms["remove_preserved"].transform(regs)
        regs = transforms["special_to_underscore"].transform(regs)

    def generate(self, regs, outpath):
        try:
            self.setup_registers(regs)

            for reg in regs:
                include_guard = "PAL_" + reg.name.upper() + "_H"
                self.gadgets["shoulder.include_guard"].name = include_guard
                self.gadgets["shoulder.header_depends"].includes = [
                    "<stdint.h>"
                ]

                outfile_path = os.path.join(outpath, reg.name.lower() + ".h")
                outfile_path = os.path.abspath(outfile_path)

                with open(outfile_path, "w") as outfile:
                    self.gadgets["shoulder.cxx.namespace"].name = "pal"
                    self._generate_register(outfile, reg)

            self.gadgets["shoulder.cxx.namespace"].indent_contents = False

        except Exception as e:
            msg = "{g} failed to generate output {out}: {exception}".format(
                g=str(type(self).__name__),
                out=outpath,
                exception=e)
            raise ShoulderGeneratorException(msg)

    # -------------------------------------------------------------------------
    # private
    # -------------------------------------------------------------------------

    @shoulder.gadget.license
    @shoulder.gadget.include_guard
    @shoulder.gadget.header_depends
    @shoulder.gadget.cxx.namespace
    #  @shoulder.gadget.external_component
    def _generate_register(self, outfile, reg):
        self.writer.write_newline(outfile)
        self._generate_register_comment(outfile, reg)

        self.gadgets["shoulder.cxx.namespace"].name = reg.name.lower()
        self.gadgets["shoulder.cxx.namespace"].indent_contents = True
        self._generate_register_accessors(outfile, reg)

    def _generate_register_comment(self, outfile, reg):
        comment = "{name} ({long_name})\n".format(
            name=str(reg.name),
            long_name=str(reg.long_name)
        )
        self.writer.declare_comment(outfile, comment, wrap=75)
        self.writer.declare_comment(outfile, str(reg.purpose), wrap=75)

    @shoulder.gadget.cxx.namespace
    def _generate_register_accessors(self, outfile, reg):
        self.writer.declare_register_constants(outfile, reg)

        if reg.is_readable():
            self.writer.declare_register_get(outfile, reg)
        if reg.is_writeable():
            self.writer.declare_register_set(outfile, reg)
        fieldsets = reg.fieldsets

        for idx, fieldset in enumerate(fieldsets):
            if len(fieldsets) > 1:
                self.writer.delcare_comment(outfile, fieldset.condition)
                self.gadgets["shoulder.cxx.namespace"].name = "fieldset_" + str(idx + 1)
                self._generate_fieldset_in_namespace(outfile, reg, fieldsets[0])
            else:
                self._generate_fieldset(outfile, reg, fieldsets[0])

    @shoulder.gadget.cxx.namespace
    def _generate_fieldset_in_namespace(self, outfile, reg, fieldset):
        self._generate_fieldset(outfile, reg, fieldset)

    def _generate_fieldset(self, outfile, reg, fieldset):
        for idx, field in enumerate(fieldset.fields):
            if field.description:
                self.writer.declare_comment(outfile, field.description, wrap=71)

            self.gadgets["shoulder.cxx.namespace"].name = field.name.lower()
            self._generate_register_field(outfile, reg, field)
            self.writer.write_newline(outfile)

        if reg.is_readable():
            self.writer.declare_fieldset_printer(outfile, reg, fieldset)

    @shoulder.gadget.cxx.namespace
    def _generate_register_field(self, outfile, reg, field):
        self.writer.declare_field_constants(outfile, reg, field)
        self.writer.declare_field_accessors(outfile, reg, field)
        self.writer.declare_field_printer(outfile, reg, field)

    def _generate_external_constants(self, outfile, reg, am):
        pass
        #  declare_variable("offset", value=str(am.offset), constexpr=True,
        #                   const=True, size=reg.size)
