from typing import TextIO
from shoulder.logger import logger


def write_inline_assembly(outfile, statements, outputs="", inputs="",
                          clobbers=""):
    outfile.write("__asm__ __volatile__(\n")
    for statement in statements:
        outfile.write("    \"" + str(statement) + ";\"\n")

    outfile.write("    : " + str(outputs) + "\n")
    outfile.write("    : " + str(inputs) + "\n")
    outfile.write("    : " + str(clobbers) + "\n")

    outfile.write(");\n")
