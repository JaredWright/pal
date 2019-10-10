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

from dataclasses import dataclass, field as datafield
from typing import List, Dict

from shoulder.logger import logger
from shoulder.model.register import Register
from shoulder.model.fieldset import Fieldset
from shoulder.model.access_mechanism import AbstractAccessMechanism


@dataclass
class x86_64Register(Register):
    """ Models a register in the Intel x86_64 architecture """

    arch: str = "x86_64"

    execution_states: Dict[str, bool] \
        = datafield(default_factory= lambda: {
            "real_mode": True,
            "protected_mode": True,
            "64bit_mode": True,
            "compatibility_mode": True,
            "virtual_8086": True,
        })

    arch_variants: Dict[str, bool] \
        = datafield(default_factory= lambda: {
            "skylake": True,
            "goldmont": True,
            "kaby_lake": True,
            "coffee_lake": True,
            "goldmont_plus": True,
            "cannon_lake": True,
            "whiskey_lake": True,
            "amber_lake": True,
            "cascade_lake": True,
            "comet_lake": True,
            "ice_lake": True,
        })

    access_mechanisms: Dict[str, List[AbstractAccessMechanism]] \
        = datafield(default_factory= lambda: {
            "rdmsr": [],
            "wrmsr": [],
            "cpuid": [],
            "vmread": [],
            "vmwrite": [],
        })
