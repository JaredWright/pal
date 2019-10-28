from shoulder.writer.abstract_writer import AbstractWriter

from shoulder.writer.language.cxx11 import Cxx11LanguageWriter

from shoulder.writer.access_mechanism.gas_x86_64_intel_syntax import \
    GasX86_64IntelSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.gas_x86_64_att_syntax import \
    GasX86_64AttSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.c_unit_test import \
    CUnitTestAccessMechanismWriter

from shoulder.writer.file_format.unix import UnixFileFormatWriter
from shoulder.writer.file_format.windows import WindowsFileFormatWriter

language_options = {
    "c++11": Cxx11LanguageWriter,
}

access_mechanism_options = {
    "gas_x86_64_intel_syntax": GasX86_64IntelSyntaxAccessMechanismWriter,
    "gas_x86_64_att_syntax": GasX86_64AttSyntaxAccessMechanismWriter,
    "c_unit_test": CUnitTestAccessMechanismWriter,
}

file_format_options = {
    "unix": UnixFileFormatWriter,
    "windows": WindowsFileFormatWriter,
}


def make_writer(language, access_mechanism, file_format):

    if language not in language_options:
        raise Exception("invalid language option: " + str(language))

    if access_mechanism not in access_mechanism_options:
        raise Exception("invalid access_mechanism option: " + str(access_mechanism))

    if file_format not in file_format_options:
        raise Exception("invalid file_format option: " + str(file_format))

    class Writer(
            AbstractWriter,
            language_options[language],
            access_mechanism_options[access_mechanism],
            file_format_options[file_format]
          ):
        pass

    return Writer()
