#ifndef BEECRYTP_COMPAT_H
#define BEECRYTP_COMPAT_H

#include <string.h>

#ifndef ROTL32
# define ROTL32(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#endif
#ifndef ROTR32
# define ROTR32(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
#endif

#define MP_WBITS 32
#define WORDS_BIGENDIAN (G_BYTE_ORDER == G_BIG_ENDIAN)
#define MP_WORDS_TO_BYTES(x)   ((x) << 2)
#define MP_BITS_TO_WORDS(x)    ((x) >> 5) 
#define mpmove(size, dst, src) memmove(dst, src, MP_WORDS_TO_BYTES(size))

#define BEECRYPTAPI

typedef guchar byte;
typedef guint32 mpw;

typedef enum
{
        NOCRYPT,
        ENCRYPT,
        DECRYPT
} cipherOperation;

#endif /* BEECRYTP_COMPAT_H */
