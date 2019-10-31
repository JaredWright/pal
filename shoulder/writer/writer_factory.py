from shoulder.writer.abstract_writer import AbstractWriter

from shoulder.writer.language.cxx11 import Cxx11LanguageWriter
from shoulder.writer.language.cxx11_unit_test import Cxx11UnitTestLanguageWriter
from shoulder.writer.language.none import NoneLanguageWriter

from shoulder.writer.access_mechanism.gas_x86_64_intel_syntax import \
    GasX86_64IntelSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.gas_x86_64_att_syntax import \
    GasX86_64AttSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.none import \
    NoneAccessMechanismWriter

from shoulder.writer.printer.printf_utf8 import PrintfUtf8PrinterWriter
from shoulder.writer.printer.none import NonePrinterWriter

from shoulder.writer.file_format.unix import UnixFileFormatWriter
from shoulder.writer.file_format.windows import WindowsFileFormatWriter
from shoulder.writer.file_format.none import NoneFileFormatWriter

language_options = {
    "c++11": Cxx11LanguageWriter,
    "c++11_unit_test": Cxx11UnitTestLanguageWriter,
    None: NoneLanguageWriter,
}

access_mechanism_options = {
    "gas_x86_64_intel_syntax": GasX86_64IntelSyntaxAccessMechanismWriter,
    "gas_x86_64_att_syntax": GasX86_64AttSyntaxAccessMechanismWriter,
    None: NoneAccessMechanismWriter,
}

printer_options = {
    "printf_utf8": PrintfUtf8PrinterWriter,
    None: NonePrinterWriter,
}

file_format_options = {
    "unix": UnixFileFormatWriter,
    "windows": WindowsFileFormatWriter,
    None: NoneFileFormatWriter,
}


def make_writer(language, access_mechanism, printer, file_format):

    if language not in language_options:
        raise Exception("invalid language option: " + str(language))

    if access_mechanism not in access_mechanism_options:
        raise Exception("invalid access_mechanism option: " + str(access_mechanism))

    if printer not in printer_options:
        raise Exception("invalid printer option: " + str(printer))

    if file_format not in file_format_options:
        raise Exception("invalid file_format option: " + str(file_format))

    class Writer(
            AbstractWriter,
            language_options[language],
            access_mechanism_options[access_mechanism],
            printer_options[printer],
            file_format_options[file_format]
          ):
        pass

    return Writer()
