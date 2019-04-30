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
import textwrap

from shoulder.generator.abstract_generator import AbstractGenerator
from shoulder.logger import logger
from shoulder.config import config
from shoulder.exception import ShoulderGeneratorException
from shoulder.filter import filters
from shoulder.transform import transforms
import shoulder.gadget


class CHeaderGenerator2(AbstractGenerator):
    def generate(self, objects, outpath):
        try:
            regs = objects

            regs = transforms["remove_reserved_0"].transform(regs)
            regs = transforms["remove_reserved_1"].transform(regs)
            #  regs = transforms["remove_coprocessor_am"].transform(regs)
            #  regs = transforms["remove_memory_mapped_am"].transform(regs)
            #  regs = transforms["remove_system_vector_am"].transform(regs)
            #  regs = transforms["remove_system_banked_am"].transform(regs)
            #  regs = transforms["remove_system_immediate_am"].transform(regs)
            regs = transforms["unique_fieldset_names"].transform(regs)

            regs = filters["no_access_mechanism"].filter_exclusive(regs)

            outfile_path = os.path.abspath(os.path.join(outpath, "shoulder.h"))
            logger.info("Generating C Header: " + str(outfile_path))
            with open(outfile_path, "w") as outfile:
                self._generate(outfile, regs)

        except Exception as e:
            msg = "{g} failed to generate output {out}: {exception}".format(
                g=str(type(self).__name__),
                out=outpath,
                exception=e)
            raise ShoulderGeneratorException(msg)

    @shoulder.gadget.license
    @shoulder.gadget.include_guard
    @shoulder.gadget.header_depends
    def _generate(self, outfile, regs):
        for reg in regs:
            self._generate_register_comment(outfile, reg)

            gadget = self.gadgets["shoulder.c.function_definition"]
            gadget.indent = 0

            if reg.size == 32:
                gadget.return_type = "uint32_t"
            else:
                gadget.return_type = "uint64_t"

            #  if reg.access_mechanisms["mrs_register"]:
            #      am = reg.access_mechanisms["mrs_register"][0]
            #      self._generate_mrs_register_accessor(outfile, reg, am)
            #
            #  elif reg.access_mechanisms["mrs_banked"]:
            #      am = reg.access_mechanisms["mrs_banked"][0]
            #      self._generate_mrs_banked_accessor(outfile, reg, am)
            #
            #  elif reg.access_mechanisms["mrc"]:
            #      am = reg.access_mechanisms["mrc"][0]
            #      self._generate_mrc_accessor(outfile, reg, am)
            #
            #  elif reg.access_mechanisms["mrrc"]:
            #      am = reg.access_mechanisms["mrrc"][0]
            #      self._generate_mrrc_accessor(outfile, reg, am)
            #
            #  elif reg.access_mechanisms["vmrs"]:
            #      am = reg.access_mechanisms["vmrs"][0]
            #      self._generate_vmrs_accessor(outfile, reg, am)
            #
            #  elif reg.access_mechanisms["ldr"]:
            #      am = reg.access_mechanisms["ldr"][0]
            #      self._generate_ldr_accessor(outfile, reg, am)

            self._generate_register_get(outfile, reg)
            self._generate_register_set(outfile, reg)

            gadget.indent = 1
            for fieldset in reg.fieldsets:
                self._generate_fieldset_comment(outfile, fieldset)

                for field in fieldset.fields:
                    if field.msb == field.lsb:
                        self._generate_bitfield_enable(outfile, reg, field)
                        self._generate_bitfield_enable_val(outfile, reg, field)
                        self._generate_bitfield_is_enabled(outfile, reg, field)
                        self._generate_bitfield_is_enabled_val(outfile, reg, field)
                        self._generate_bitfield_disable(outfile, reg, field)
                        self._generate_bitfield_disable_val(outfile, reg, field)
                        self._generate_bitfield_is_disabled(outfile, reg, field)
                        self._generate_bitfield_is_disabled_val(outfile, reg, field)
                    else:
                        self._generate_field_get(outfile, reg, field)
                        self._generate_field_get_val(outfile, reg, field)
                        self._generate_field_set(outfile, reg, field)
                        self._generate_field_set_val(outfile, reg, field)

    def _generate_register_comment(self, outfile, reg):
        comment = "// {name} ({long_name})\n".format(
            name=str(reg.name),
            long_name=str(reg.long_name)
        )
        outfile.write(comment)

        comment = str(reg.purpose)
        wrapped = textwrap.wrap(comment, width=75)
        for line in wrapped:
            line = "// " + str(line) + "\n"
            outfile.write(line)

    def _generate_fieldset_comment(self, outfile, fieldset):
        if fieldset.condition is not None:
            fieldset_comment = "Fieldset valid when: {comment}\n".format(
                comment=str(fieldset.condition))
            wrapped = textwrap.wrap(fieldset_comment, width=71)
            for line in wrapped:
                line = "\t// " + str(line) + "\n"
                outfile.write(line)

# ----------------------------------------------------------------------------
# register_get
# ----------------------------------------------------------------------------

    def _generate_register_get(self, outfile, reg):
        """
        Generate a C function that reads the given register
        """

        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + reg.name.lower() + "_get"
        gadget.args = []

        if reg.access_mechanisms["mrs_register"]:
            am = reg.access_mechanisms["mrs_register"][0]
            self._generate_mrs_register_accessor(outfile, reg, am)

        elif reg.access_mechanisms["mrs_banked"]:
            am = reg.access_mechanisms["mrs_banked"][0]
            self._generate_mrs_banked_accessor(outfile, reg, am)

        elif reg.access_mechanisms["mrc"]:
            am = reg.access_mechanisms["mrc"][0]
            self._generate_mrc_accessor(outfile, reg, am)

        elif reg.access_mechanisms["mrrc"]:
            am = reg.access_mechanisms["mrrc"][0]
            self._generate_mrrc_accessor(outfile, reg, am)

        elif reg.access_mechanisms["vmrs"]:
            am = reg.access_mechanisms["vmrs"][0]
            self._generate_vmrs_accessor(outfile, reg, am)

        elif reg.access_mechanisms["ldr"]:
            am = reg.access_mechanisms["ldr"][0]
            self._generate_ldr_accessor(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_mrs_register_accessor(self, outfile, reg, am):
        reg_getter = "GET_SYSREG_FUNC({encoded})".format(
            encoded=hex(am.binary_encoded()))
        outfile.write(reg_getter)

    @shoulder.gadget.c.function_definition
    def _generate_mrs_banked_accessor(self, outfile, reg, am):
        outfile.write("TODO: mrs_banked")

    @shoulder.gadget.c.function_definition
    def _generate_mrc_accessor(self, outfile, reg, am):
        outfile.write("TODO: mrc")

    @shoulder.gadget.c.function_definition
    def _generate_mrrc_accessor(self, outfile, reg, am):
        outfile.write("TODO: mrrc")

    @shoulder.gadget.c.function_definition
    def _generate_vmrs_accessor(self, outfile, reg, am):
        outfile.write("TODO: vmrs")

    @shoulder.gadget.c.function_definition
    def _generate_ldr_accessor(self, outfile, reg, am):
        outfile.write("TODO: ldr")

# ----------------------------------------------------------------------------
# register_set
# ----------------------------------------------------------------------------

    def _generate_register_set(self, outfile, reg):
        """
        Generate a C function that writes the given register
        """

        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type
        gadget.name = "aarch64_" + reg.name.lower() + "_set"
        gadget.args = [(size_type, "val")]

        if reg.access_mechanisms["msr_register"]:
            am = reg.access_mechanisms["msr_register"][0]
            self._generate_msr_register_accessor(outfile, reg, am)

        elif reg.access_mechanisms["mcr"]:
            am = reg.access_mechanisms["mcr"][0]
            self._generate_mcr_accessor(outfile, reg, am)

        elif reg.access_mechanisms["mcrr"]:
            am = reg.access_mechanisms["mcrr"][0]
            self._generate_mcrr_accessor(outfile, reg, am)

        elif reg.access_mechanisms["msr_banked"]:
            am = reg.access_mechanisms["msr_banked"][0]
            self._generate_msr_banked_accessor(outfile, reg, am)

        elif reg.access_mechanisms["msr_immediate"]:
            am = reg.access_mechanisms["msr_immediate"][0]
            self._generate_msr_immediate_accessor(outfile, reg, am)

        elif reg.access_mechanisms["str"]:
            am = reg.access_mechanisms["str"][0]
            self._generate_str_accessor(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_msr_register_accessor(self, outfile, reg, am):
        reg_setter = "SET_SYSREG_BY_VALUE_FUNC({access_name}, val)".format(
            access_name=hex(am.binary_encoded()))
        outfile.write(reg_setter)

    @shoulder.gadget.c.function_definition
    def _generate_mcr_accessor(self, outfile, reg, am):
        outfile.write("TODO: mcr")

    @shoulder.gadget.c.function_definition
    def _generate_mcrr_accessor(self, outfile, reg, am):
        outfile.write("TODO: mcrr")

    @shoulder.gadget.c.function_definition
    def _generate_msr_banked_accessor(self, outfile, reg, am):
        outfile.write("TODO: msr_banked")

    @shoulder.gadget.c.function_definition
    def _generate_msr_immediate_accessor(self, outfile, reg, am):
        outfile.write("TODO: msr_immediate")

    @shoulder.gadget.c.function_definition
    def _generate_vmsr_accessor(self, outfile, reg, am):
        outfile.write("TODO: vmsr")

    @shoulder.gadget.c.function_definition
    def _generate_str_accessor(self, outfile, reg, am):
        outfile.write("TODO: str")

# ----------------------------------------------------------------------------
# bitfield_enable
# ----------------------------------------------------------------------------
    def _generate_bitfield_enable(self, outfile, reg, field):
        """
        Generate a C function that enables the given bitfield (to 1) in the
        given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_enable"
        gadget.args = []

        if reg.access_mechanisms["msr_register"]:
            am = reg.access_mechanisms["msr_register"][0]
            self._generate_msr_bitfield_enable(outfile, reg, field, am)

        elif reg.access_mechanisms["mcr"]:
            am = reg.access_mechanisms["mcr"][0]
            self._generate_mcr_bitfield_enable(outfile, reg, am)

        elif reg.access_mechanisms["mcrr"]:
            am = reg.access_mechanisms["mcrr"][0]
            self._generate_mcrr_bitfield_enable(outfile, reg, am)

        elif reg.access_mechanisms["msr_banked"]:
            am = reg.access_mechanisms["msr_banked"][0]
            self._generate_msr_banked_bitfield_enable(outfile, reg, am)

        elif reg.access_mechanisms["msr_immediate"]:
            am = reg.access_mechanisms["msr_immediate"][0]
            self._generate_msr_immediate_bitfield_enable(outfile, reg, am)

        elif reg.access_mechanisms["str"]:
            am = reg.access_mechanisms["str"][0]
            self._generate_str_bitfield_enable(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_msr_bitfield_enable(self, outfile, reg, field, am):
        outfile.write("TODO: set bitfield using msr")

    @shoulder.gadget.c.function_definition
    def _generate_mcr_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using mcr")

    @shoulder.gadget.c.function_definition
    def _generate_mcrr_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using mcrr")

    @shoulder.gadget.c.function_definition
    def _generate_msr_banked_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using msr_banked")

    @shoulder.gadget.c.function_definition
    def _generate_msr_immediate_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using msr_immediate")

    @shoulder.gadget.c.function_definition
    def _generate_vmsr_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using vmsr")

    @shoulder.gadget.c.function_definition
    def _generate_str_bitfield_enable(self, outfile, reg, am):
        outfile.write("TODO: set bitfield using str")

# ----------------------------------------------------------------------------
# bitfield_enable_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_enable_val(self, outfile, reg, field):
        """
        Generate a C function that sets the given bitfield (1) in an integer
        value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_enable_val"
        gadget.args = [(size_type, "arg1"), (size_type, "arg2")]

        self._bitfield_enable_val(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _bitfield_enable_val(self, outfile, reg, field):
        func = "SET_BITS_BY_MASK_FUNC(val, {mask})".format(mask=field.lsb)
        outfile.write(func)

# ----------------------------------------------------------------------------
# bitfield_is_enabled
# ----------------------------------------------------------------------------

    def _generate_bitfield_is_enabled(self, outfile, reg, field):
        """
        Generate a C function that checks if the given bitfield is set (1) in
        the given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_is_enabled"
        gadget.args = []

        if reg.access_mechanisms["msr_register"]:
            am = reg.access_mechanisms["msr_register"][0]
            self._generate_msr_bitfield_is_enabled(outfile, reg, field, am)

        elif reg.access_mechanisms["mcr"]:
            am = reg.access_mechanisms["mcr"][0]
            self._generate_mcr_bitfield_is_enabled(outfile, reg, am)

        elif reg.access_mechanisms["mcrr"]:
            am = reg.access_mechanisms["mcrr"][0]
            self._generate_mcrr_bitfield_is_enabled(outfile, reg, am)

        elif reg.access_mechanisms["msr_banked"]:
            am = reg.access_mechanisms["msr_banked"][0]
            self._generate_msr_banked_bitfield_is_enabled(outfile, reg, am)

        elif reg.access_mechanisms["msr_immediate"]:
            am = reg.access_mechanisms["msr_immediate"][0]
            self._generate_msr_immediate_bitfield_is_enabled(outfile, reg, am)

        elif reg.access_mechanisms["str"]:
            am = reg.access_mechanisms["str"][0]
            self._generate_str_bitfield_is_enabled(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_msr_bitfield_is_enabled(self, outfile, reg, field, am):
        func = "IS_SYSREG_BIT_ENABLED_FUNC({accessname}, {lsb})".format(
            accessname=hex(am.binary_encoded()),
            lsb=field.lsb
        )
        outfile.write(func)

    @shoulder.gadget.c.function_definition
    def _generate_mcr_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using mcr")

    @shoulder.gadget.c.function_definition
    def _generate_mcrr_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using mcrr")

    @shoulder.gadget.c.function_definition
    def _generate_msr_banked_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using msr_banked")

    @shoulder.gadget.c.function_definition
    def _generate_msr_immediate_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using msr_immediate")

    @shoulder.gadget.c.function_definition
    def _generate_vmsr_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using vmsr")

    @shoulder.gadget.c.function_definition
    def _generate_str_bitfield_is_enabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield enabled using str")

# ----------------------------------------------------------------------------
# bitfield_is_enabled_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_enabled_val(self, outfile, reg, field):
        """
        Generate a C function that checks if the given bitfield is enabled (1)
        in an integer value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_is_enabled_val"
        gadget.args = [(size_type, "val")]

        self._generate_bitfield_is_enabled_value(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _generate_bitfield_is_enabled_value(self, outfile, reg, field):
        func = "IS_BIT_ENABLED_FUNC(val, {lsb})".format(lsb=field.lsb)
        outfile.write(func)

# ----------------------------------------------------------------------------
# bitfield_disable
# ----------------------------------------------------------------------------
    def _generate_bitfield_disable(self, outfile, reg, field):
        """
        Generate a C function that disables the given bitfield (to 1) in the
        given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_disable"
        gadget.args = []

        if reg.access_mechanisms["msr_register"]:
            am = reg.access_mechanisms["msr_register"][0]
            self._generate_msr_bitfield_disable(outfile, reg, field, am)

        elif reg.access_mechanisms["mcr"]:
            am = reg.access_mechanisms["mcr"][0]
            self._generate_mcr_bitfield_disable(outfile, reg, am)

        elif reg.access_mechanisms["mcrr"]:
            am = reg.access_mechanisms["mcrr"][0]
            self._generate_mcrr_bitfield_disable(outfile, reg, am)

        elif reg.access_mechanisms["msr_banked"]:
            am = reg.access_mechanisms["msr_banked"][0]
            self._generate_msr_banked_bitfield_disable(outfile, reg, am)

        elif reg.access_mechanisms["msr_immediate"]:
            am = reg.access_mechanisms["msr_immediate"][0]
            self._generate_msr_immediate_bitfield_disable(outfile, reg, am)

        elif reg.access_mechanisms["str"]:
            am = reg.access_mechanisms["str"][0]
            self._generate_str_bitfield_disable(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_msr_bitfield_disable(self, outfile, reg, field, am):
        outfile.write("TODO: clear bitfield using msr")

    @shoulder.gadget.c.function_definition
    def _generate_mcr_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using mcr")

    @shoulder.gadget.c.function_definition
    def _generate_mcrr_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using mcrr")

    @shoulder.gadget.c.function_definition
    def _generate_msr_banked_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using msr_banked")

    @shoulder.gadget.c.function_definition
    def _generate_msr_immediate_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using msr_immediate")

    @shoulder.gadget.c.function_definition
    def _generate_vmsr_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using vmsr")

    @shoulder.gadget.c.function_definition
    def _generate_str_bitfield_disable(self, outfile, reg, am):
        outfile.write("TODO: clear bitfield using str")

# ----------------------------------------------------------------------------
# bitfield_disable_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_disable_val(self, outfile, reg, field):
        """
        Generate a C function that clears the given bitfield (1) in an integer
        value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_disable_val"
        gadget.args = [(size_type, "arg1"), (size_type, "arg2")]

        self._bitfield_disable_val(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _bitfield_disable_val(self, outfile, reg, field):
        func = "CLEAR_BITS_BY_MASK_FUNC(val, {mask})".format(mask=field.lsb)
        outfile.write(func)

# ----------------------------------------------------------------------------
# bitfield_is_disabled
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_disabled(self, outfile, reg, field):
        """
        Generate a C function that checks if the given bitfield is disabled (0)
        in the given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_is_disabled"
        gadget.args = []

        if reg.access_mechanisms["msr_register"]:
            am = reg.access_mechanisms["msr_register"][0]
            self._generate_msr_bitfield_is_disabled(outfile, reg, field, am)

        elif reg.access_mechanisms["mcr"]:
            am = reg.access_mechanisms["mcr"][0]
            self._generate_mcr_bitfield_is_disabled(outfile, reg, am)

        elif reg.access_mechanisms["mcrr"]:
            am = reg.access_mechanisms["mcrr"][0]
            self._generate_mcrr_bitfield_is_disabled(outfile, reg, am)

        elif reg.access_mechanisms["msr_banked"]:
            am = reg.access_mechanisms["msr_banked"][0]
            self._generate_msr_banked_bitfield_is_disabled(outfile, reg, am)

        elif reg.access_mechanisms["msr_immediate"]:
            am = reg.access_mechanisms["msr_immediate"][0]
            self._generate_msr_immediate_bitfield_is_disabled(outfile, reg, am)

        elif reg.access_mechanisms["str"]:
            am = reg.access_mechanisms["str"][0]
            self._generate_str_bitfield_is_disabled(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_msr_bitfield_is_disabled(self, outfile, reg, field, am):
        func = "IS_SYSREG_BIT_DISABLED_FUNC({accessname}, {lsb})".format(
            accessname=hex(am.binary_encoded()),
            lsb=field.lsb
        )
        outfile.write(func)

    @shoulder.gadget.c.function_definition
    def _generate_mcr_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using mcr")

    @shoulder.gadget.c.function_definition
    def _generate_mcrr_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using mcrr")

    @shoulder.gadget.c.function_definition
    def _generate_msr_banked_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using msr_banked")

    @shoulder.gadget.c.function_definition
    def _generate_msr_immediate_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using msr_immediate")

    @shoulder.gadget.c.function_definition
    def _generate_vmsr_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using vmsr")

    @shoulder.gadget.c.function_definition
    def _generate_str_bitfield_is_disabled(self, outfile, reg, am):
        outfile.write("TODO: check bitfield disabled using str")

# ----------------------------------------------------------------------------
# bitfield_is_disabled_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_disabled_val(self, outfile, reg, field):
        """
        Generate a C function that checks if the given bitfield is cleared (0)
        in an integer value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_is_disabled_val"
        gadget.args = [(size_type, "val")]

        self._generate_bitfield_is_disabled_value(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _generate_bitfield_is_disabled_value(self, outfile, reg, field):
        func = "IS_BIT_DISABLED_FUNC(val, {lsb})".format(lsb=field.lsb)
        outfile.write(func)

# ----------------------------------------------------------------------------
# field_get
# ----------------------------------------------------------------------------
    def _generate_field_get(self, outfile, reg, field):
        """
        Generate a C function that reads the given field from the given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_get"
        gadget.args = []

        if reg.access_mechanisms["mrs_register"]:
            am = reg.access_mechanisms["mrs_register"][0]
            self._generate_mrs_register_field_get(outfile, reg, am)

        elif reg.access_mechanisms["mrs_banked"]:
            am = reg.access_mechanisms["mrs_banked"][0]
            self._generate_mrs_banked_field_get(outfile, reg, am)

        elif reg.access_mechanisms["mrc"]:
            am = reg.access_mechanisms["mrc"][0]
            self._generate_mrc_field_get(outfile, reg, am)

        elif reg.access_mechanisms["mrrc"]:
            am = reg.access_mechanisms["mrrc"][0]
            self._generate_mrrc_field_get(outfile, reg, am)

        elif reg.access_mechanisms["vmrs"]:
            am = reg.access_mechanisms["vmrs"][0]
            self._generate_vmrs_field_get(outfile, reg, am)

        elif reg.access_mechanisms["ldr"]:
            am = reg.access_mechanisms["ldr"][0]
            self._generate_ldr_field_get(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_mrs_register_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using mrs_register")

    @shoulder.gadget.c.function_definition
    def _generate_mrs_banked_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using mrs_banked")

    @shoulder.gadget.c.function_definition
    def _generate_mrc_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using mrc")

    @shoulder.gadget.c.function_definition
    def _generate_mrrc_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using mrrc")

    @shoulder.gadget.c.function_definition
    def _generate_vmrs_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using vmrs")

    @shoulder.gadget.c.function_definition
    def _generate_ldr_field_get(self, outfile, reg, am):
        outfile.write("TODO: get field using ldr")

# ----------------------------------------------------------------------------
# field_get_val
# ----------------------------------------------------------------------------
    def _generate_field_get_val(self, outfile, reg, field):
        """
        Generate a C function that reads the given field from an integer value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_get_val"
        gadget.args = [(size_type, "val")]

        self._generate_field_get_val_(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _generate_field_get_val_(self, outfile, reg, field):
        outfile.write("TODO: get field from integer value")

# ----------------------------------------------------------------------------
# field_set
# ----------------------------------------------------------------------------
    def _generate_field_set(self, outfile, reg, field):
        """
        Generate a C function that writes the given field to the given register
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        gadget.name = "aarch64_" + rname + "_" + fname + "_set"
        size_type = gadget.return_type
        gadget.args = [(size_type, "val")]

        if reg.access_mechanisms["mrs_register"]:
            am = reg.access_mechanisms["mrs_register"][0]
            self._generate_mrs_register_field_set(outfile, reg, am)

        elif reg.access_mechanisms["mrs_banked"]:
            am = reg.access_mechanisms["mrs_banked"][0]
            self._generate_mrs_banked_field_set(outfile, reg, am)

        elif reg.access_mechanisms["mrc"]:
            am = reg.access_mechanisms["mrc"][0]
            self._generate_mrc_field_set(outfile, reg, am)

        elif reg.access_mechanisms["mrrc"]:
            am = reg.access_mechanisms["mrrc"][0]
            self._generate_mrrc_field_set(outfile, reg, am)

        elif reg.access_mechanisms["vmrs"]:
            am = reg.access_mechanisms["vmrs"][0]
            self._generate_vmrs_field_set(outfile, reg, am)

        elif reg.access_mechanisms["ldr"]:
            am = reg.access_mechanisms["ldr"][0]
            self._generate_ldr_field_set(outfile, reg, am)

    @shoulder.gadget.c.function_definition
    def _generate_mrs_register_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using mrs_register")

    @shoulder.gadget.c.function_definition
    def _generate_mrs_banked_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using mrs_banked")

    @shoulder.gadget.c.function_definition
    def _generate_mrc_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using mrc")

    @shoulder.gadget.c.function_definition
    def _generate_mrrc_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using mrrc")

    @shoulder.gadget.c.function_definition
    def _generate_vmrs_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using vmrs")

    @shoulder.gadget.c.function_definition
    def _generate_ldr_field_set(self, outfile, reg, am):
        outfile.write("TODO: set field using ldr")

# ----------------------------------------------------------------------------
# field_set_val
# ----------------------------------------------------------------------------
    def _generate_field_set_val(self, outfile, reg, field):
        """
        Generate a C function that writes the given field to an integer value
        """

        rname = reg.name.lower()
        fname = field.name.lower()
        gadget = self.gadgets["shoulder.c.function_definition"]
        size_type = gadget.return_type

        gadget.name = "aarch64_" + rname + "_" + fname + "_set_val"
        gadget.args = [(size_type, "arg1"), (size_type, "arg2")]

        self._generate_field_set_val_(outfile, reg, field)

    @shoulder.gadget.c.function_definition
    def _generate_field_set_val_(self, outfile, reg, field):
        outfile.write("TODO: set field to integer value")
