# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import cffi

from cryptography.hazmat.bindings.utils import build_ffi


class Binding(object):
    """
    CommonCrypto API wrapper.
    """
    _module_prefix = "cryptography.hazmat.bindings.gcrypt."
    _modules = [
        "main",
    ]

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        cls.ffi, cls.lib = build_ffi(cls._module_prefix, cls._modules,
                                     "", "", ["gcrypt"])

    @classmethod
    def is_available(cls):
        try:
            ffi = cffi.FFI()
            ffi.verify('#include "gcrypt.h"')
            return True
        except cffi.VerificationError:
            return False
