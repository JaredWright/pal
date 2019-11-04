from pal.parser.abstract_parser import AbstractParser
from pal.logger import logger
from pal.exception import PalParserException
#  import pal.model
#  import pal.model.armv8a
#  import pal.model.armv8a.access_mechanism
import pal.model.x86_64
import pal.model.x86_64.access_mechanism


class BfMsrParser(AbstractParser):
    def parse_file(self, path):
        registers = []

        try:
            with open(path, "r") as infile:
                register = None
                fieldset = None
                field = None
                msr_addr = ""
                registers = []

                for line in infile:
                    if line.startswith("<--msr_name-->"):
                        register = pal.model.x86_64.register.x86_64Register()
                        fieldset = pal.model.Fieldset()
                        register.fieldsets.append(fieldset)
                        fieldset.size = 64
                        fieldset.name = "latest"
                        fieldset.condition = "Fieldset valid on latest "
                        fieldset.condition += "version of the Intel architecture"
                        fieldset.fields = []
                        self._set_register_name(register, line)
                        continue

                    if line.startswith("    <--msr_long_name-->"):
                        self._set_register_long_name(register, line)
                        continue

                    if line.startswith("    <--msr_addr-->"):
                        self._set_register_long_name(register, line)
                        msr_addr = self._strip_string(line[18:-1])
                        continue

                    if line.startswith("    <--msr_is_readable-->"):
                        self._set_register_rdmsr_mechanism(register, msr_addr)
                        continue

                    if line.startswith("    <--msr_is_writable-->"):
                        self._set_register_wrmsr_mechanism(register, msr_addr)
                        continue

                    if line.startswith("}"):
                        registers.append(register)
                        continue

                    if line.startswith("    <--field_name-->"):
                        field = pal.model.Field()
                        self._add_field_to_register(register, field, line)
                        continue

                    if line.startswith("        <--field_lsb-->"):
                        self._set_field_lsb(field, line)
                        continue

                    if line.startswith("        <--field_mask-->"):
                        self._set_field_msb(field, line)
                        continue

                    if line.startswith("        <--field_long_name-->"):
                        self._set_field_long_name(field, line)
                        continue

                    if line.startswith("        <--field_is_readable-->"):
                        field.readable = True
                        continue

                    if line.startswith("        <--field_is_writable-->"):
                        field.writable = True
                        continue

        except Exception as e:
            msg = "Failed to parse register file " + str(path)
            msg += ": " + str(e)
            raise PalParserException(msg)

        for r in registers:
            logger.info(str(r))
        return registers

    def _set_register_name(self, register, line):
        register.name = self._strip_string(line[14:-1])

    def _set_register_long_name(self, register, line):
        register.long_name = self._strip_string(line[23:])

    def _set_register_rdmsr_mechanism(self, register, address):
        am = pal.model.x86_64.access_mechanism.rdmsr.RDMSR(address)
        register.access_mechanisms["rdmsr"].append(am)

    def _set_register_wrmsr_mechanism(self, register, address):
        am = pal.model.x86_64.access_mechanism.wrmsr.WRMSR(address)
        register.access_mechanisms["wrmsr"].append(am)

    def _add_field_to_register(self, register, field, line):
        field.name = self._strip_string(line[20:])
        register.fieldsets[0].fields.append(field)
        pass

    def _set_field_lsb(self, field, line):
        field.lsb = self._strip_string(line[23:-1])

    def _set_field_msb(self, field, line):
        mask_str = line[24:-1]
        mask_bin = bin(int(mask_str, 16))[2:]
        field.msb = len(mask_bin) - 1

    def _set_field_long_name(self, field, line):
        field.long_name = self._strip_string(line[29:-2])

    def _strip_string(self, string):
        if string.startswith("\""):
            return self._strip_string(string[1:])
        elif string.startswith("\ "):
            return self._strip_string(string[1:])

        elif string.endswith("\n"):
            return self._strip_string(string[:-1])
        elif string.endswith("\""):
            return self._strip_string(string[:-1])
        elif string.endswith(";"):
            return self._strip_string(string[:-1])
        elif string.endswith("\ "):
            return self._strip_string(string[:-1])

        return string
