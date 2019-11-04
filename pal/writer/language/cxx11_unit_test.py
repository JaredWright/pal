import pal.gadget
from pal.writer.language.cxx11 import Cxx11LanguageWriter


class Cxx11UnitTestLanguageWriter(Cxx11LanguageWriter):

    def declare_register_constants(self, outfile, register):
        self._declare_string_constant(outfile, "name", register.name.lower())
        self.write_newline(outfile)

        if register.long_name:
            self._declare_string_constant(outfile, "long_name", register.long_name)
            self.write_newline(outfile)

        if register.access_mechanisms["rdmsr"]:
            addr = register.access_mechanisms["rdmsr"][0].address
            self._declare_hex_integer_constant(outfile, "address", addr)
            self.write_newline(outfile)

        if register.size == 32:
            size_t = "uint32_t"
        else:
            size_t = "uint64_t"

        self._declare_variable(outfile, "mock_register", value=0,
                               keywords=["static", size_t])

        self.write_newline(outfile)

    @pal.gadget.cxx.function_definition
    def _declare_register_get_details(self, outfile, register):
        outfile.write("return mock_register;")
        self.write_newline(outfile)

    @pal.gadget.cxx.function_definition
    def _declare_register_set_details(self, outfile, register):
        outfile.write("mock_register = value;")
        self.write_newline(outfile)
