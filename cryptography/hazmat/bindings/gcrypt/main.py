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

INCLUDES = """
#include "gcrypt.h"
"""

TYPES = """
static const char *const GCRYPT_VERSION;
enum gcry_md_algos {
    GCRY_MD_NONE    = 0,
    GCRY_MD_MD5     = 1,
    GCRY_MD_SHA1    = 2,
    GCRY_MD_RMD160  = 3,
    GCRY_MD_MD2     = 5,
    GCRY_MD_TIGER   = 6,   /* TIGER/192 as used by gpg <= 1.3.2. */
    GCRY_MD_HAVAL   = 7,   /* HAVAL, 5 pass, 160 bit. */
    GCRY_MD_SHA256  = 8,
    GCRY_MD_SHA384  = 9,
    GCRY_MD_SHA512  = 10,
    GCRY_MD_SHA224  = 11,
    GCRY_MD_MD4     = 301,
    GCRY_MD_CRC32         = 302,
    GCRY_MD_CRC32_RFC1510 = 303,
    GCRY_MD_CRC24_RFC2440 = 304,
    GCRY_MD_WHIRLPOOL = 305,
    GCRY_MD_TIGER1  = 306, /* TIGER fixed.  */
    GCRY_MD_TIGER2  = 307  /* TIGER2 variant.   */
};
enum gcry_md_flags {
    GCRY_MD_FLAG_SECURE = 1,  /* Allocate all buffers in "secure" memory.  */
    GCRY_MD_FLAG_HMAC   = 2   /* Make an HMAC out of this algorithm.  */
};

struct gcry_md_context;
typedef struct gcry_md_handle {
    /* Actual context.  */
    struct gcry_md_context *ctx;

    /* Buffer management.  */
    int  bufpos;
    int  bufsize;
    unsigned char buf[1];
} *gcry_md_hd_t;

typedef uint32_t gcry_error_t;

/* cipher reqs */
struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *gcry_cipher_hd_t;

enum gcry_cipher_algos {
    GCRY_CIPHER_NONE        = 0,
    GCRY_CIPHER_IDEA        = 1,
    GCRY_CIPHER_3DES        = 2,
    GCRY_CIPHER_CAST5       = 3,
    GCRY_CIPHER_BLOWFISH    = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK      = 6,
    GCRY_CIPHER_AES         = 7,
    GCRY_CIPHER_AES192      = 8,
    GCRY_CIPHER_AES256      = 9,
    GCRY_CIPHER_TWOFISH     = 10,

    /* Other cipher numbers are above 300 for OpenPGP reasons. */
    GCRY_CIPHER_ARCFOUR     = 301,  /* Fully compatible with RSA's RC4 (tm). */
    GCRY_CIPHER_DES         = 302,  /* Yes, this is single key 56 bit DES. */
    GCRY_CIPHER_TWOFISH128  = 303,
    GCRY_CIPHER_SERPENT128  = 304,
    GCRY_CIPHER_SERPENT192  = 305,
    GCRY_CIPHER_SERPENT256  = 306,
    GCRY_CIPHER_RFC2268_40  = 307,  /* Ron's Cipher 2 (40 bit). */
    GCRY_CIPHER_RFC2268_128 = 308,  /* Ron's Cipher 2 (128 bit). */
    GCRY_CIPHER_SEED        = 309,  /* 128 bit cipher described in RFC4269. */
    GCRY_CIPHER_CAMELLIA128 = 310,
    GCRY_CIPHER_CAMELLIA192 = 311,
    GCRY_CIPHER_CAMELLIA256 = 312
};

enum gcry_cipher_modes {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5,  /* Outer feedback. */
    GCRY_CIPHER_MODE_CTR    = 6,  /* Counter. */
    GCRY_CIPHER_MODE_AESWRAP= 7   /* AES-WRAP algorithm.  */
};

enum gcry_cipher_flags {
    GCRY_CIPHER_SECURE      = 1,  /* Allocate in secure memory. */
    GCRY_CIPHER_ENABLE_SYNC = 2,  /* Enable CFB sync mode. */
    GCRY_CIPHER_CBC_CTS     = 4,  /* Enable CBC cipher text stealing (CTS). */
    GCRY_CIPHER_CBC_MAC     = 8   /* Enable CBC message auth. code (MAC). */
};

"""

FUNCTIONS = """
gcry_error_t gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);

/* Release the message digest object HD.  */
void gcry_md_close (gcry_md_hd_t hd);

/* Add the message digest algorithm ALGO to the digest object HD.  */
gcry_error_t gcry_md_enable (gcry_md_hd_t hd, int algo);

/* Create a new digest object as an exact copy of the object HD.  */
gcry_error_t gcry_md_copy (gcry_md_hd_t *bhd, gcry_md_hd_t ahd);

/* Reset the digest object HD to its initial state.  */
void gcry_md_reset (gcry_md_hd_t hd);

/* Perform various operations on the digest object HD. */
gcry_error_t gcry_md_ctl (gcry_md_hd_t hd, int cmd,
                          void *buffer, size_t buflen);

/* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
   it can update the digest values.  This is the actual hash
   function. */
void gcry_md_write (gcry_md_hd_t hd, const void *buffer, size_t length);

/* Read out the final digest from HD return the digest value for
   algorithm ALGO. */
unsigned char *gcry_md_read (gcry_md_hd_t hd, int algo);

/* Convenience function to calculate the hash from the data in BUFFER
   of size LENGTH using the algorithm ALGO avoiding the creating of a
   hash object.  The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
void gcry_md_hash_buffer (int algo, void *digest,
                          const void *buffer, size_t length);

/* For use with the HMAC feature, the set MAC key to the KEY of
   KEYLEN bytes. */
gcry_error_t gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen);

/* Cipher functions */
/* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
   be given as an bitwise OR of the gcry_cipher_flags values. */
gcry_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
                              int algo, int mode, unsigned int flags);

/* Close the cioher handle H and release all resource. */
void gcry_cipher_close (gcry_cipher_hd_t h);

/* Encrypt the plaintext of size INLEN in IN using the cipher handle H
   into the buffer OUT which has an allocated length of OUTSIZE.  For
   most algorithms it is possible to pass NULL for in and 0 for INLEN
   and do a in-place decryption of the data provided in OUT.  */
gcry_error_t gcry_cipher_encrypt (gcry_cipher_hd_t h,
                                  void *out, size_t outsize,
                                  const void *in, size_t inlen);

/* The counterpart to gcry_cipher_encrypt.  */
gcry_error_t gcry_cipher_decrypt (gcry_cipher_hd_t h,
                                  void *out, size_t outsize,
                                  const void *in, size_t inlen);

/* Set KEY of length KEYLEN bytes for the cipher handle HD.  */
gcry_error_t gcry_cipher_setkey (gcry_cipher_hd_t hd,
                                 const void *key, size_t keylen);


/* Set initialization vector IV of length IVLEN for the cipher handle HD. */
gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t hd,
                                const void *iv, size_t ivlen);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
