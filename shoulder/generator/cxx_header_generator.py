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

from shoulder.writer.gcc.access_mechanism import call_readable_access_mechanism
from shoulder.writer.gcc.access_mechanism import call_writable_access_mechanism

class CxxHeaderGenerator(AbstractGenerator):
    def generate(self, regs, outpath):
        try:
            #  regs = transforms["remove_reserved_0"].transform(regs)
            #  regs = transforms["remove_reserved_1"].transform(regs)
            #  regs = transforms["remove_reserved_sign_extended"].transform(regs)
            #  regs = transforms["remove_implementation_defined"].transform(regs)
            #  regs = transforms["special_to_underscore"].transform(regs)
            #  regs = transforms["remove_redundant_am"].transform(regs)
            #  regs = transforms["remove_redundant_fields"].transform(regs)
            #
            #  regs = filters["no_access_mechanism"].filter_exclusive(regs)
            #  if config.encoded_functions:
            #      msg = "Encoded accessors are only supported for aarch64 "
            #      msg += "registers (aarch32 and external not supported)"
            #      logger.warn(msg)
            #      regs = filters["aarch64"].filter_inclusive(regs)

            #  unique = []
            #  for reg in regs:
            #      external_mechs = reg.access_mechanisms["ldr"] + \
            #                       reg.access_mechanisms["str"]
            #      for mech in external_mechs:
            #          if mech.component not in unique:
            #              unique.append(mech.component)
            #  self.gadgets["shoulder.external_component"].components = unique

            for reg in regs:
                self.gadgets["shoulder.header_depends"].includes = [
                    "<stdint.h>",
                    #  "aarch32_gcc_accessor_macros.h",
                    #  "aarch64_gcc_accessor_macros.h"
                ]

                inc_guard_name = "SHOULDER_" + reg.name.upper() + "_H"
                self.gadgets["shoulder.include_guard"].name = inc_guard_name
                outfile_path = os.path.abspath(os.path.join(outpath,
                                                            reg.name.lower() + ".h"))
                with open(outfile_path, "w") as outfile:
                    self._generate(outfile, [reg])

        except Exception as e:
            msg = "{g} failed to generate output {out}: {exception}".format(
                g=str(type(self).__name__),
                out=outpath,
                exception=e)
            raise ShoulderGeneratorException(msg)

    @shoulder.gadget.license
    @shoulder.gadget.include_guard
    @shoulder.gadget.header_depends
    #  @shoulder.gadget.external_component
    def _generate(self, outfile, regs):
        self.gadgets["shoulder.cxx.namespace"].name = "pal"
        #  aarch64_regs = filters["aarch64"].filter_inclusive(regs)
        #  if aarch64_regs:
        self._generate_register_group(outfile, regs)
            #  outfile.write("\n")

        #  self.gadgets["shoulder.cxx.namespace"].name = "aarch32"
        #  aarch32_regs = filters["aarch32"].filter_inclusive(regs)
        #  if aarch32_regs:
        #      self._generate_register_group(outfile, aarch32_regs)
        #      outfile.write("\n")
        #
        #  self.gadgets["shoulder.cxx.namespace"].name = "external"
        #  external_regs = filters["external"].filter_inclusive(regs)
        #  if external_regs:
        #      self._generate_register_group(outfile, external_regs)
        #      outfile.write("\n")

    @shoulder.gadget.cxx.namespace
    def _generate_register_group(self, outfile, regs):
        for reg in regs:
            self.gadgets["shoulder.cxx.namespace"].name = reg.name.lower()
            self.gadgets["shoulder.cxx.namespace"].indent_contents = True

            outfile.write("\n")
            self._generate_register_comment(outfile, reg)
            self._generate_register(outfile, reg)

        self.gadgets["shoulder.cxx.namespace"].indent_contents = False

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

    @shoulder.gadget.cxx.namespace
    def _generate_register(self, outfile, reg):
        """
        Generate C++ accessors for the given register
        """
        self._generate_register_constants(outfile, reg)
        if reg.is_readable():
            self._generate_register_get(outfile, reg)
        if reg.is_writeable():
            self._generate_register_set(outfile, reg)

        fieldsets = reg.fieldsets

        for idx, fieldset in enumerate(reg.fieldsets):
            if len(fieldsets) > 1:
                self._generate_fieldset_comment(outfile, fieldset, idx + 1)
                self.gadgets["shoulder.cxx.namespace"].name = "fieldset_" + str(idx + 1)
                self._generate_fieldset_in_namespace(outfile, reg, fieldsets[0])
            else:
                self._generate_fieldset(outfile, reg, fieldsets[0])

    def _generate_register_constants(self, outfile, reg):
        """
        Generate constants that describe the given register
        """

        constants = "constexpr const auto name = \"{name}\";\n"
        constants = constants.format(
            name=reg.name
        )

        if reg.long_name and reg.long_name.lower() != reg.name.lower():
            constants += "constexpr const auto long_name = \"{long_name}\";\n"
            constants = constants.format(long_name=reg.long_name)

        outfile.write(constants)
        outfile.write("\n")

    @shoulder.gadget.cxx.namespace
    def _generate_fieldset_in_namespace(self, outfile, reg, fieldset):
        self._generate_fieldset(outfile, reg, fieldset)

    def _generate_fieldset(self, outfile, reg, fieldset):
        for idx, field in enumerate(fieldset.fields):
            self.gadgets["shoulder.cxx.namespace"].name = field.name.lower()
            self._generate_field_comment(outfile, field)
            self._generate_register_field(outfile, reg, field)

            if not idx == len(fieldset.fields) - 1:
                outfile.write("\n")

    @shoulder.gadget.cxx.namespace
    def _generate_register_field(self, outfile, reg, field):
        """
        Generate C++ accessors for the given register field
        """
        self._generate_field_constants(outfile, reg, field)
        if field.msb == field.lsb:
            self._generate_bitfield_set(outfile, reg, field)
            self._generate_bitfield_set_val(outfile, reg, field)
            self._generate_bitfield_is_set(outfile, reg, field)
            self._generate_bitfield_is_set_val(outfile, reg, field)
            self._generate_bitfield_clear(outfile, reg, field)
            self._generate_bitfield_clear_val(outfile, reg, field)
            self._generate_bitfield_is_clear(outfile, reg, field)
            self._generate_bitfield_is_clear_val(outfile, reg, field)
        else:
            self._generate_field_get(outfile, reg, field)
            self._generate_field_get_val(outfile, reg, field)
            self._generate_field_set(outfile, reg, field)
            self._generate_field_set_val(outfile, reg, field)

    def _generate_fieldset_comment(self, outfile, fieldset, idx):
        if fieldset.condition:
            fieldset_comment = "Fieldset {i}: {comment}\n".format(
                i=idx,
                comment=str(fieldset.condition)
            )
            wrapped = textwrap.wrap(fieldset_comment, width=71)
            for line in wrapped:
                line = "// " + str(line) + "\n"
                outfile.write(line)

    def _generate_register_get(self, outfile, reg):
        """
        Generate a C++ function that reads the given register
        """
        gadget = self.gadgets["shoulder.cxx.function_definition"]
        gadget.name = config.register_read_function
        gadget.return_type = self._register_size_type(reg)
        gadget.args = []

        if reg.is_indexed:
            gadget.args = [("uint32_t", "index")]
            gadget.name = gadget.name + "_at_index"

        self._generate_register_get_body(outfile, reg)

    @shoulder.gadget.cxx.function_definition
    def _generate_register_get_body(self, outfile, reg):
        for am_key, am_list in reg.access_mechanisms.items():
            for am in am_list:
                if am.is_read():
                    call_readable_access_mechanism(outfile, reg, am)
                    return

        msg = "Register {r} has no readable access mechanism"
        msg = msg.format(r=str(reg.name))
        logger.error(msg)
        raise ShoulderGeneratorException(msg)

    def _generate_register_set(self, outfile, reg):
        """
        Generate a C++ function that writes the given register
        """
        size_type = self._register_size_type(reg)
        gadget = self.gadgets["shoulder.cxx.function_definition"]
        gadget.name = config.register_write_function
        gadget.return_type = "void"
        gadget.args = [(size_type, "val")]

        self._generate_register_set_body(outfile, reg)

    @shoulder.gadget.cxx.function_definition
    def _generate_register_set_body(self, outfile, reg):
        for am_key, am_list in reg.access_mechanisms.items():
            for am in am_list:
                if am.is_write():
                    gadget = self.gadgets["shoulder.cxx.function_definition"]
                    arg_name = gadget.args[0][1]
                    call_writable_access_mechanism(outfile, reg, am, arg_name)
                    return

        msg = "Register {r} has no writable access mechanism"
        msg = msg.format(r=str(reg.name))
        logger.error(msg)
        raise ShoulderGeneratorException(msg)

# ----------------------------------------------------------------------------
# constants
# ----------------------------------------------------------------------------

    def _generate_external_constants(self, outfile, reg, am):
        """
        Generate constants that describe the address offset of the given register
        """

        constants = "constexpr const {size} offset = {offset};\n"
        constants += "\n"
        constants = constants.format(
            size=self._register_size_type(reg),
            offset=am.offset
        )

        outfile.write(constants)

    def _generate_field_comment(self, outfile, field):
        """
        Generate a comment that describes the given field in the given register
        """
        if field.description:
            wrapped = textwrap.wrap(field.description, width=71)
            for line in wrapped:
                line = "// " + str(line) + "\n"
                outfile.write(line)

    def _generate_field_constants(self, outfile, reg, field):
        """
        Generate constants that describe the given field in the given register
        """

        constants = "constexpr const {size} lsb = {lsb};\n"
        constants += "constexpr const {size} msb = {msb};\n"
        constants += "constexpr const {size} mask = {mask};\n"
        constants += "constexpr const auto name = \"{name}\";\n"
        constants = constants.format(
            lsb=str(field.lsb),
            msb=str(field.msb),
            size=self._register_size_type(reg),
            mask=self._field_mask_hex_string(reg, field),
            name=field.name
        )

        if field.long_name and field.long_name.lower() != field.name.lower():
            constants += "constexpr const auto long_name = \"{long_name}\";\n"
            constants = constants.format(long_name=field.long_name)

        outfile.write(constants)
        outfile.write("\n")

# ----------------------------------------------------------------------------
# bitfield_set
# ----------------------------------------------------------------------------
    def _generate_bitfield_set(self, outfile, reg, field):
        """
        Generate a C++ function that sets/enables the given bitfield (to 1) in
        the given register
        """

        if reg.is_writeable():
            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = []
            gadget.name = "{name}".format(
                name=config.bit_set_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._bitfield_set(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_set(self, outfile, reg, field):
        f_body = "{reg_set}({reg_get}() | {mask});".format(
            mask=self._field_mask_string(reg, field),
            reg_get=self._register_read_function_name(reg),
            reg_set=self._register_write_function_name(reg)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_set_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_set_val(self, outfile, reg, field):
        """
        Generate a C++ function that sets the given bitfield (1) in an integer
        value
        """

        if reg.is_writeable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = [(size_type, "&val")]
            gadget.name = "{name}".format(
                name=config.bit_set_function
            )

            self._bitfield_set_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_set_val(self, outfile, reg, field):
        f_body = "val |= {mask};".format(
            mask=self._field_mask_string(reg, field)
        )
        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_is_set
# ----------------------------------------------------------------------------

    def _generate_bitfield_is_set(self, outfile, reg, field):
        """
        Generate a C++ function that checks if the given bitfield is set (1) in
        the given register
        """
        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = []
            gadget.name = "{name}".format(
                name=config.is_bit_set_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._bitfield_is_set(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_is_set(self, outfile, reg, field):
        f_body = "return ({reg_get}() & {mask}) != 0;".format(
            mask=self._field_mask_string(reg, field),
            reg_get=self._register_read_function_name(reg),
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_is_set_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_set_val(self, outfile, reg, field):
        """
        Generate a C++ function that checks if the given bitfield is set/enabled
        (to 1) in an integer value
        """

        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = [(size_type, "val")]
            gadget.name = "{name}".format(
                name=config.is_bit_set_function
            )

            self._bitfield_is_set_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_is_set_val(self, outfile, reg, field):
        f_body = "return (val & {mask}) != 0;"

        f_body = f_body.format(
            mask=self._field_mask_string(reg, field)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_disable
# ----------------------------------------------------------------------------
    def _generate_bitfield_clear(self, outfile, reg, field):
        """
        Generate a C++ function that disables the given bitfield (to 1) in the
        given register
        """

        if reg.is_writeable():
            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = []
            gadget.name = "{name}".format(
                name=config.bit_clear_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._bitfield_clear(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_clear(self, outfile, reg, field):
        f_body = "{reg_set}({reg_get}() & ~{mask});".format(
            mask=self._field_mask_string(reg, field),
            reg_get=self._register_read_function_name(reg),
            reg_set=self._register_write_function_name(reg)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_clear_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_clear_val(self, outfile, reg, field):
        """
        Generate a C++ function that clears the given bitfield (1) in an integer
        value
        """

        if reg.is_writeable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = [(size_type, "&val")]
            gadget.name = "{name}".format(
                name=config.bit_clear_function
            )

            self._bitfield_clear_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_clear_val(self, outfile, reg, field):
        f_body = "val &= ~{mask};".format(
            mask=self._field_mask_string(reg, field)
        )
        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_is_disabled
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_clear(self, outfile, reg, field):
        """
        Generate a C++ function that checks if the given bitfield is disabled (0)
        in the given register
        """

        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = []
            gadget.name = "{name}".format(
                name=config.is_bit_cleared_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._bitfield_is_clear(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_is_clear(self, outfile, reg, field):
        f_body = "return ({reg_get}() & {mask}) == 0;".format(
            size=self._register_size_type(reg),
            mask=self._field_mask_string(reg, field),
            reg_get=self._register_read_function_name(reg),
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# bitfield_is_disabled_val
# ----------------------------------------------------------------------------
    def _generate_bitfield_is_clear_val(self, outfile, reg, field):
        """
        Generate a C++ function that checks if the given bitfield is cleared (0)
        in an integer value
        """

        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = [(size_type, "val")]
            gadget.name = "{name}".format(
                name=config.is_bit_cleared_function
            )

            self._bitfield_is_clear_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _bitfield_is_clear_val(self, outfile, reg, field):
        f_body = "return (val & {mask}) == 0;"

        f_body = f_body.format(
            size=self._register_size_type(reg),
            mask=self._field_mask_string(reg, field),
            reg_get=self._register_read_function_name(reg),
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# field_get
# ----------------------------------------------------------------------------
    def _generate_field_get(self, outfile, reg, field):
        """
        Generate a C++ function that reads the given field from the given register
        """

        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = []
            gadget.name = "{name}".format(
                name=config.register_field_read_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._field_get(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _field_get(self, outfile, reg, field):
        f_body = "return ({reg_get}() & {mask}) >> {lsb};".format(
            mask=self._field_mask_string(reg, field),
            lsb=self._field_lsb_string(reg, field),
            reg_get=self._register_read_function_name(reg)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# field_get_val
# ----------------------------------------------------------------------------
    def _generate_field_get_val(self, outfile, reg, field):
        """
        Generate a C++ function that reads the given field from an integer value
        """

        if reg.is_readable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = size_type
            gadget.args = [(size_type, "val")]
            gadget.name = "{name}".format(
                name=config.register_field_read_function
            )

            self._field_get_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _field_get_val(self, outfile, reg, field):
        f_body = "return (val & {mask}) >> {lsb};"

        f_body = f_body.format(
            size=self._register_size_type(reg),
            mask=self._field_mask_string(reg, field),
            lsb=self._field_lsb_string(reg, field)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# field_set
# ----------------------------------------------------------------------------
    def _generate_field_set(self, outfile, reg, field):
        """
        Generate a C++ function that writes the given field to the given register
        """

        if reg.is_writeable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = [(size_type, "val")]
            gadget.name = "{name}".format(
                name=config.register_field_write_function
            )

            if reg.is_indexed:
                gadget.args.append(("uint32_t", "index"))
                gadget.name = gadget.name + "_at_index"

            self._field_set(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _field_set(self, outfile, reg, field):
        f_body = "{size} reg = ({reg_get}() & ~{mask})\n"
        f_body += "\t| ((val << {lsb}) & {mask});\n"
        f_body += "{reg_set}(reg);"

        f_body = f_body.format(
            size=self._register_size_type(reg),
            mask=self._field_mask_string(reg, field),
            lsb=self._field_lsb_string(reg, field),
            reg_get=self._register_read_function_name(reg),
            reg_set=self._register_write_function_name(reg)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# field_set_val
# ----------------------------------------------------------------------------
    def _generate_field_set_val(self, outfile, reg, field):
        """
        Generate a C++ function that writes the given field to an integer value
        """

        if reg.is_writeable():
            size_type = self._register_size_type(reg)

            gadget = self.gadgets["shoulder.cxx.function_definition"]
            gadget.return_type = "void"
            gadget.args = [(size_type, "field_val"), (size_type, "&reg_val")]
            gadget.name = "{name}".format(
                name=config.register_field_write_function
            )

            self._field_set_val(outfile, reg, field)

    @shoulder.gadget.cxx.function_definition
    def _field_set_val(self, outfile, reg, field):
        f_body = "reg_val = (reg_val & ~{mask})\n\t"
        f_body += "| ((field_val << {lsb}) & {mask});"

        f_body = f_body.format(
            size=self._register_size_type(reg),
            mask=self._field_mask_string(reg, field),
            lsb=self._field_lsb_string(reg, field)
        )

        outfile.write(f_body)

# ----------------------------------------------------------------------------
# utilities
# ----------------------------------------------------------------------------
    def _field_mask_hex_string(self, reg, field):
        mask_val = 0
        for i in range(field.lsb, field.msb + 1):
            mask_val |= 1 << i

        if reg.size == 32:
            return "{0:#0{1}x}".format(mask_val, 10)
        else:
            return "{0:#0{1}x}".format(mask_val, 18)

    def _field_mask_string(self, reg, field):
        return "{field}::mask".format(
            field=field.name.lower()
        )

    def _field_lsb_string(self, reg, field):
        return "{field}::lsb".format(
            field=field.name.lower()
        )

    def _register_size_type(self, reg):
        if reg.size == 32:
            return "uint32_t"
        else:
            return "uint64_t"

    def _register_read_function_name(self, reg):
        return "{reg_name}::{read}".format(
            reg_name=reg.name.lower(),
            read=config.register_read_function
        )

    def _register_write_function_name(self, reg):
        return "{reg_name}::{write}".format(
            reg_name=reg.name.lower(),
            write=config.register_write_function
        )
