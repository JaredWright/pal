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


import unittest
import os

from shoulder.generator.cxx_header_generator import CxxHeaderGenerator
from shoulder.register import Register
from shoulder.logger import logger
from test.support.constants import *

TEST_OUTFILE = os.path.abspath(os.path.join(TEST_TOP_DIR, "out/output.txt"))

class TestCxxHeaderGenerator(unittest.TestCase):

    def test_generator_init(self):
        r = Register()
        r.name = "TESTREG_EL2"
        r.long_name = "Test Register (EL2)"
        r.purpose = "Does stuff for aarch64 at exception level 2"
        r.size = 64

        fs = Fieldset(r.size)
        #  fs.condition = "the condition under which this fieldset is used"
        fs.add_field("msb", 63, 63)
        fs.add_field("not_msb_lsb", 62, 1)
        fs.add_field("lsb", 0, 0)
        r.add_fieldset(fs)

        regs = [r]
        g = CxxHeaderGenerator()
        g.generate(regs, TEST_OUTFILE)
