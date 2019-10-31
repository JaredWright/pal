from shoulder.writer.printer.printer import PrinterWriter


class NoPrintPrinterWriter(PrinterWriter):

    def declare_fieldset_printer(self, outfile, register, fieldset):
        pass

    def declare_field_printer(self, outfile, register, field):
        pass
