from shoulder.generator.cxx.base_generator import CxxBaseGenerator
from shoulder.transform import transforms
from shoulder.writer.cxx.variable import declare_variable
from shoulder.writer.cxx.variable import declare_string
from shoulder.writer.cxx.variable import assign_variable
from shoulder.writer.cxx.variable import return_variable
from shoulder.writer.formating import write_newline


class UnitTestGenerator(CxxBaseGenerator):

    def setup_registers(self, regs):
        regs = transforms["remove_reserved_0"].transform(regs)
        regs = transforms["remove_reserved_1"].transform(regs)
        regs = transforms["remove_preserved"].transform(regs)
        regs = transforms["special_to_underscore"].transform(regs)

    def generate_register_variables(self, outfile, reg):
        declare_string(outfile, "name", value=reg.name, constexpr=True,
                       const=True)

        if reg.long_name and reg.long_name.lower() != reg.name.lower():
            declare_string(outfile, "long_name", value=reg.long_name,
                           constexpr=True, const=True)

        if reg.access_mechanisms["rdmsr"]:
            addr = reg.access_mechanisms["rdmsr"][0].address
            declare_variable(outfile, "address", value=addr, size=reg.size,
                             constexpr=True, const=True)

        declare_variable(outfile, "unit_test_register", value=0, size=reg.size,
                         static=True)

        write_newline(outfile)

    def generate_register_get_details(self, outfile, register):
        return_variable(outfile, "unit_test_register")

    def generate_register_set_details(self, outfile, register):
        assign_variable(outfile, "unit_test_register", "val")
