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
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
