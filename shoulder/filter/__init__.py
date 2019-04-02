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

import os
import sys
import pkgutil

pkg_dir = os.path.dirname(__file__)
for (module_loader, name, ispkg) in pkgutil.iter_modules([pkg_dir]):
    pkgutil.importlib.import_module('.' + name, __package__)

# -----------------------------------------------------------------------------
# Module interface
# -----------------------------------------------------------------------------

# Usage:
#
# from shoulder.filters import filters
# registers = filters["filter_name"].filter_exclusive(registers)
# registers = filters["filter_name"].filter_inclusive(registers)

filters = {
    "activity_monitor": activity_monitor.ActivityMonitorRegisterFilter(),
    "deprecated": deprecated.DeprecatedRegisterFilter(),
    "gic": gic.GICRegisterFilter(),
    "invalid": invalid.InvalidRegisterFilter(),
    "loregion": loregion.LORegionRegisterFilter(),
    "misc": misc.MiscelaneousRegisterFilter(),
    "mpam": mpam.MPAMRegisterFilter(),
    "scxtnum": scxtnum.SCXTNUMRegisterFilter(),
    "statistical_profiling": statistical_profiling.StatisticalProfilingRegisterFilter(),
    "sve": sve.SVERegisterFilter(),
    "trace": trace.TraceRegisterFilter()
}