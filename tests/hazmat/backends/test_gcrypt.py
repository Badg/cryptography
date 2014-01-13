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

import pytest

from cryptography.hazmat.bindings.gcrypt.binding import Binding


@pytest.mark.skipif(not Binding.is_available(),
                    reason="gcrypt not available")
class TestGcrypt(object):
    def test_backend_handle_error(self):
        from cryptography.hazmat.backends.gcrypt.backend import backend
        with pytest.raises(SystemError) as exc_info:
            backend._handle_error(536870955)
        assert exc_info.value.args[0] == "Weak encryption key"
