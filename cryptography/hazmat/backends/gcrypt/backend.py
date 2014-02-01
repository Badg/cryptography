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

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend, PBKDF2HMACBackend
)
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Blowfish, Camellia, TripleDES, ARC4,
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CTR, ECB, OFB, CFB, GCM
)
from cryptography.hazmat.primitives import constant_time, interfaces
from cryptography.hazmat.bindings.gcrypt.binding import Binding


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
class Backend(object):
    """
    libgcrypt API binding interfaces.
    """
    name = "gcrypt"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib
        self._cipher_registry = {}
        self._register_default_ciphers()
        self._hashes_supported = {
            "md5": self._lib.GCRY_MD_MD5,
            "sha1": self._lib.GCRY_MD_SHA1,
            "sha224": self._lib.GCRY_MD_SHA224,
            "sha256": self._lib.GCRY_MD_SHA256,
            "sha384": self._lib.GCRY_MD_SHA384,
            "sha512": self._lib.GCRY_MD_SHA512,
            "whirlpool": self._lib.GCRY_MD_WHIRLPOOL,
            "ripemd160": self._lib.GCRY_MD_RMD160,
        }

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, key, algorithm)

    def hash_supported(self, algorithm):
        return algorithm.name in self._hashes_supported

    def hmac_supported(self, algorithm):
        return self.hash_supported(algorithm)

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def cipher_supported(self, cipher, mode):
        return (type(cipher), type(mode)) in self._cipher_registry

    def register_cipher_adapter(self, cipher_cls, mode_cls, adapter):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}".format(
                cipher_cls, mode_cls)
            )
        self._cipher_registry[cipher_cls, mode_cls] = adapter

    def _register_default_ciphers(self):
        for mode_cls in [CBC, ECB, CFB, OFB, CTR, GCM]:
            self.register_cipher_adapter(
                AES,
                mode_cls,
                GetCipherModeEnum()
            )
        for mode_cls in [CBC, ECB, CFB, OFB]:
            self.register_cipher_adapter(
                Camellia,
                mode_cls,
                GetCipherModeEnum()
            )
        for mode_cls in [CBC, CFB, OFB, ECB]:
            self.register_cipher_adapter(
                Blowfish,
                mode_cls,
                GetCipherModeEnum()
            )
        self.register_cipher_adapter(
            ARC4,
            type(None),
            GetCipherModeEnum()
        )

    def create_symmetric_encryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._ENCRYPT)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._DECRYPT)

    def pbkdf2_hmac_supported(self, algorithm):
        return algorithm.name in self._hashes_supported

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        alg_enum = self._hashes_supported[algorithm.name]
        buf = self._ffi.new("char[]", length)
        res = self._lib.gcry_kdf_derive(
            key_material,
            len(key_material),
            self._lib.GCRY_KDF_PBKDF2,
            alg_enum,
            salt,
            len(salt),
            iterations,
            length,
            buf
        )
        self._handle_error(res)

        return self._ffi.buffer(buf)[:]

    def _handle_error(self, code):
        # TODO: improve handling
        if code != 0:
            err = self._ffi.string(self._lib.gcry_strerror(code))
            raise SystemError("gcrypt returned an error: {0}".format(err))


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self.algorithm = algorithm

        self._backend = backend
        try:
            self._alg_id = self._backend._hashes_supported[algorithm.name]
        except KeyError:
            raise UnsupportedAlgorithm(
                "{0} is not a supported hash on this backend".format(
                    algorithm.name)
            )

        if ctx is None:
            ctx = self._backend._ffi.new("gcry_md_hd_t *")
            ctx[0] = self._backend._ffi.gc(
                ctx[0], self._backend._lib.gcry_md_close
            )
            # TODO: use MD secure? There appears to be limited memory for that
            res = self._backend._lib.gcry_md_open(
                ctx, self._alg_id, self._backend._lib.GCRY_MD_FLAG_SECURE
            )
            self._backend._handle_error(res)

        self._ctx = ctx

    def copy(self):
        copied_ctx = self._backend._ffi.new("gcry_md_hd_t *")
        res = self._backend._lib.gcry_md_copy(copied_ctx, self._ctx[0])
        self._backend._handle_error(res)
        return _HashContext(self._backend, self.algorithm, ctx=copied_ctx)

    def update(self, data):
        self._backend._lib.gcry_md_write(self._ctx[0], data, len(data))

    def finalize(self):
        buf = self._backend._lib.gcry_md_read(self._ctx[0], self._alg_id)
        assert buf != self._backend._ffi.NULL
        md = self._backend._ffi.buffer(buf, self.algorithm.digest_size)[:]
        self._backend._lib.gcry_md_close(self._ctx[0])
        return md


@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self.algorithm = algorithm

        self._backend = backend
        try:
            self._alg_id = self._backend._hashes_supported[algorithm.name]
        except KeyError:
            raise UnsupportedAlgorithm(
                "{0} is not a supported hash on this backend".format(
                    algorithm.name)
            )

        if ctx is None:
            ctx = self._backend._ffi.new("gcry_md_hd_t *")
            ctx[0] = self._backend._ffi.gc(
                ctx[0], self._backend._lib.gcry_md_close
            )
            # TODO: use MD secure? There appears to be limited memory for that
            res = self._backend._lib.gcry_md_open(
                ctx, self._alg_id, (self._backend._lib.GCRY_MD_FLAG_HMAC |
                                    self._backend._lib.GCRY_MD_FLAG_SECURE)
            )
            self._backend._handle_error(res)

            res = self._backend._lib.gcry_md_setkey(ctx[0], key, len(key))
            self._backend._handle_error(res)

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend._ffi.new("gcry_md_hd_t *")
        res = self._backend._lib.gcry_md_copy(copied_ctx, self._ctx[0])
        self._backend._handle_error(res)
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        self._backend._lib.gcry_md_write(self._ctx[0], data, len(data))

    def finalize(self):
        buf = self._backend._lib.gcry_md_read(self._ctx[0], self._alg_id)
        assert buf != self._backend._ffi.NULL
        md = self._backend._ffi.buffer(buf, self.algorithm.digest_size)[:]
        self._backend._lib.gcry_md_close(self._ctx[0])
        return md


class GetCipherModeEnum(object):
    def __call__(self, backend, cipher, mode):
        try:
            if type(cipher) is AES:
                cipher_enum = {
                    b"AES-128": backend._lib.GCRY_CIPHER_AES,
                    b"AES-192": backend._lib.GCRY_CIPHER_AES192,
                    b"AES-256": backend._lib.GCRY_CIPHER_AES256,
                }[b"AES-{0}".format(len(cipher.key) * 8)]
            elif type(cipher) is Camellia:
                cipher_enum = {
                    b"Camellia-128": backend._lib.GCRY_CIPHER_CAMELLIA128,
                    b"Camellia-192": backend._lib.GCRY_CIPHER_CAMELLIA192,
                    b"Camellia-256": backend._lib.GCRY_CIPHER_CAMELLIA256,
                }[b"Camellia-{0}".format(len(cipher.key) * 8)]
            else:
                cipher_enum = {
                    Blowfish: backend._lib.GCRY_CIPHER_BLOWFISH,
                    ARC4: backend._lib.GCRY_CIPHER_ARCFOUR,
                    TripleDES: backend._lib.GCRY_CIPHER_3DES,
                }[type(cipher)]
        except KeyError:
            raise UnsupportedAlgorithm

        try:
            mode_enum = {
                ECB: backend._lib.GCRY_CIPHER_MODE_ECB,
                CBC: backend._lib.GCRY_CIPHER_MODE_CBC,
                CTR: backend._lib.GCRY_CIPHER_MODE_CTR,
                CFB: backend._lib.GCRY_CIPHER_MODE_CFB,
                OFB: backend._lib.GCRY_CIPHER_MODE_OFB,
                GCM: backend._lib.GCRY_CIPHER_MODE_GCM,
                type(None): backend._lib.GCRY_CIPHER_MODE_STREAM,
            }[type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm

        return (cipher_enum, mode_enum)


@utils.register_interface(interfaces.CipherContext)
@utils.register_interface(interfaces.AEADCipherContext)
@utils.register_interface(interfaces.AEADEncryptionContext)
class _CipherContext(object):
    _ENCRYPT = 1
    _DECRYPT = 0

    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        self._tag = None
        self._byte_buffer = b""

        if (isinstance(cipher, interfaces.BlockCipherAlgorithm) and not
                isinstance(mode, (OFB, CFB, CTR, GCM))):
            self._byte_block_size = cipher.block_size // 8
        else:
            self._byte_block_size = 1

        ctx = self._backend._ffi.new("gcry_cipher_hd_t *")
        ctx[0] = self._backend._ffi.gc(
            ctx[0], self._backend._lib.gcry_cipher_close
        )

        registry = self._backend._cipher_registry
        try:
            adapter = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )
        cipher_enum, mode_enum = adapter(self._backend, cipher, mode)

        # begin init with cipher and operation type
        res = self._backend._lib.gcry_cipher_open(
            ctx, cipher_enum, mode_enum, self._backend._lib.GCRY_CIPHER_SECURE
        )
        self._backend._handle_error(res)
        # set the key
        res = self._backend._lib.gcry_cipher_setkey(
            ctx[0], self._cipher.key, len(self._cipher.key)
        )
        self._backend._handle_error(res)

        if isinstance(mode, interfaces.ModeWithInitializationVector):
            res = self._backend._lib.gcry_cipher_setiv(
                ctx[0], mode.initialization_vector,
                len(mode.initialization_vector)
            )
            self._backend._handle_error(res)
        elif isinstance(mode, interfaces.ModeWithNonce):
            res = self._backend._lib.gcry_cipher_setctr(
                ctx[0], mode.nonce, len(mode.nonce)
            )
            self._backend._handle_error(res)

        self._ctx = ctx

    def update(self, data):
        # TODO: less inefficient
        if self._byte_block_size > 1:
            data = self._byte_buffer + data
            if len(data) % self._byte_block_size:
                remainder = -1 * (len(data) % self._byte_block_size)
                self._byte_buffer = data[remainder:]
                data = data[:remainder]
            else:
                self._byte_buffer = b""
        buflen = len(data)
        buf = self._backend._ffi.new("unsigned char[]", buflen)
        if self._operation == self._ENCRYPT:
            res = self._backend._lib.gcry_cipher_encrypt(
                self._ctx[0], buf, buflen, data, len(data)
            )
            self._backend._handle_error(res)
        else:
            res = self._backend._lib.gcry_cipher_decrypt(
                self._ctx[0], buf, buflen, data, len(data)
            )
            self._backend._handle_error(res)
        return self._backend._ffi.buffer(buf)[:]

    def finalize(self):
        if isinstance(self._mode, GCM):
            tag_buf = self._backend._ffi.new(
                "unsigned char[]", self._cipher.block_size // 8
            )
            res = self._backend._lib.gcry_cipher_gettag(
                self._ctx[0], tag_buf, self._cipher.block_size // 8
            )
            self._backend._handle_error(res)
            self._tag = self._backend._ffi.buffer(tag_buf)[:]
            # gcry_cipher_checktag does not allow truncation.
            # That is laudable but we want compatibility with our other
            # backends so let's do our own constant time comparison
            if self._operation == self._DECRYPT and not constant_time.bytes_eq(
                self._tag[:len(self._mode.tag)], self._mode.tag
            ):
                self._backend._lib.gcry_cipher_close(self._ctx[0])
                raise InvalidTag
        self._backend._lib.gcry_cipher_close(self._ctx[0])
        if len(self._byte_buffer) != 0:
            raise ValueError(
                "The length of the provided data is not a multiple of "
                "the block length"
            )
        return b""

    def authenticate_additional_data(self, data):
        res = self._backend._lib.gcry_cipher_authenticate(
            self._ctx[0], data, len(data)
        )
        self._backend._handle_error(res)

    @property
    def tag(self):
        return self._tag


backend = Backend()
