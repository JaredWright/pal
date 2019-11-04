from shoulder.writer.abstract_writer import AbstractWriter

from shoulder.writer.language.cxx11 import Cxx11LanguageWriter
from shoulder.writer.language.none import NoneLanguageWriter

from shoulder.writer.access_mechanism.gas_x86_64_intel_syntax import \
    GasX86_64IntelSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.gas_x86_64_att_syntax import \
    GasX86_64AttSyntaxAccessMechanismWriter
from shoulder.writer.access_mechanism.cxx_test import \
    CxxTestAccessMechanismWriter
from shoulder.writer.access_mechanism.none import \
    NoneAccessMechanismWriter

from shoulder.writer.printer.printf_utf8 import PrintfUtf8PrinterWriter
from shoulder.writer.printer.none import NonePrinterWriter

from shoulder.writer.file_format.unix import UnixFileFormatWriter
from shoulder.writer.file_format.windows import WindowsFileFormatWriter
from shoulder.writer.file_format.none import NoneFileFormatWriter

language_options = {
    "c++11": Cxx11LanguageWriter,
    "none": NoneLanguageWriter,
}

access_mechanism_options = [
    "gas_intel",
    "gas_att",
    "test",
    "none",
]

printer_options = {
    "printf_utf8": PrintfUtf8PrinterWriter,
    "none": NonePrinterWriter,
}

file_format_options = {
    "unix": UnixFileFormatWriter,
    "windows": WindowsFileFormatWriter,
    "none": NoneFileFormatWriter,
}


def get_access_mechanism_writer(arch, language, access_mechanism):
    if arch == "intel_x64" and access_mechanism == "gas_intel":
        return GasX86_64IntelSyntaxAccessMechanismWriter
    elif arch == "intel_x64" and access_mechanism == "gas_att":
        return GasX86_64AttSyntaxAccessMechanismWriter
    elif access_mechanism == "test" and language == "c++11":
        return CxxTestAccessMechanismWriter
    else:
        return NoneAccessMechanismWriter


def make_writer(arch, language, access_mechanism, printer, file_format):

    if language not in language_options:
        raise Exception("invalid language option: " + str(language))

    if access_mechanism not in access_mechanism_options:
        raise Exception("invalid access mechanism option: " + str(access_mechanism))

    if printer not in printer_options:
        raise Exception("invalid printer option: " + str(printer))

    if file_format not in file_format_options:
        raise Exception("invalid file_format option: " + str(file_format))

    am_writer = get_access_mechanism_writer(arch, language, access_mechanism)

    class Writer(
            AbstractWriter,
            language_options[language],
            am_writer,
            printer_options[printer],
            file_format_options[file_format]
          ):
        pass

    return Writer()