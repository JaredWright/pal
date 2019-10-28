from shoulder.generator.cxx.base_generator import CxxBaseGenerator
from shoulder.exception import ShoulderGeneratorException
from shoulder.logger import logger
from shoulder.filter import filters
from shoulder.transform import transforms
from shoulder.writer.cxx.variable import declare_string
from shoulder.writer.cxx.variable import declare_variable
from shoulder.writer.formating import write_newline
from shoulder.writer.gcc.access_mechanism import call_readable_access_mechanism
from shoulder.writer.gcc.access_mechanism import call_writable_access_mechanism


class Intelx64GccGenerator(CxxBaseGenerator):

    def setup_registers(self, regs):
        #  regs = filters["intel_x64"].filter_inclusive(regs)
        regs = filters["no_access_mechanism"].filter_exclusive(regs)

        regs = transforms["remove_reserved_0"].transform(regs)
        regs = transforms["remove_reserved_1"].transform(regs)
        regs = transforms["remove_preserved"].transform(regs)
        regs = transforms["special_to_underscore"].transform(regs)

    def generate_register_variables(self, outfile, reg):
        self.writer.declare_string_constant(outfile, "name", reg.name.lower())
        self.writer.write_newline(outfile)

        if reg.long_name and reg.long_name.lower() != reg.name.lower():
            self.writer.declare_string_constant(outfile, "long_name", reg.long_name)
            self.writer.write_newline(outfile)

        if reg.access_mechanisms["rdmsr"]:
            addr = reg.access_mechanisms["rdmsr"][0].address
            self.writer.declare_hex_integer_constant(outfile, "address", addr)
            self.writer.write_newline(outfile)

        write_newline(outfile)

    def generate_register_get_details(self, outfile, register):
        for am_key, am_list in register.access_mechanisms.items():
            for access_mechanism in am_list:
                if access_mechanism.is_read():
                    size_type = self._register_size_type(register)
                    self.writer.declare_variable(outfile, "val", 0, [size_type])
                    self.writer.write_newline(outfile)
                    self.writer.call_readable_access_mechanism(
                        outfile, register, access_mechanism, "val"
                    )
                    self.writer.write_newline(outfile)
                    self.writer.return_variable(outfile, "val")
                    return

        msg = "Register {r} has no readable access mechanism"
        msg = msg.format(r=str(register.name))
        logger.error(msg)
        raise ShoulderGeneratorException(msg)

    def generate_register_set_details(self, outfile, register):
        for am_key, am_list in register.access_mechanisms.items():
            for access_mechanism in am_list:
                if access_mechanism.is_write():
                    self.writer.call_writable_access_mechanism(
                        outfile, register, access_mechanism, "val"
                    )
                    return

        msg = "Register {r} has no writable access mechanism"
        msg = msg.format(r=str(register.name))
        logger.error(msg)
        raise ShoulderGeneratorException(msg)
