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

import sys
import os

from shoulder.cmd_args import parse_cmd_args
from shoulder.parser import parse_registers
from shoulder.generator import generate_all


def shoulder_main():
    config = parse_cmd_args(sys.argv[1:])

    path = "/home/wrightj/pal_workspace/shoulder/data/x86_64/register/control_register"
    regs = parse_registers(path)
    generate_all(regs, os.path.join(config.shoulder_output_dir, "control_register"))

    path = "/home/wrightj/pal_workspace/shoulder/data/x86_64/register/cpuid"
    regs = parse_registers(path)
    generate_all(regs, os.path.join(config.shoulder_output_dir, "cpuid"))

    path = "/home/wrightj/pal_workspace/shoulder/data/x86_64/register/msr"
    regs = parse_registers(path)
    generate_all(regs, os.path.join(config.shoulder_output_dir, "msr"))

    #  path = "/home/wrightj/pal_workspace/shoulder/data/armv8-a/register/aarch64"
    #  regs = parse_registers(path)
    #  generate_all(regs, os.path.join(config.shoulder_output_dir, "aarch64"))

    #  path = "/home/wrightj/pal_workspace/shoulder/data/armv8-a/register/aarch32"
    #  regs = parse_registers(path)
    #  generate_all(regs, os.path.join(config.shoulder_output_dir, "aarch32"))

    #  path = "/home/wrightj/pal_workspace/shoulder/data/armv8-a/register/external"
    #  regs = parse_registers(path)
    #  generate_all(regs, os.path.join(config.shoulder_output_dir, "external"))

shoulder_main()
