/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2002 Virtual Unlimited B.V.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*!\file sha1.h
 * \brief SHA-1 hash function, headers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup HASH_m HASH_sha1_m
 */

/* Modified from beecrypt for gnome by Alexander Larsson <alexl@redhat.com> */

#ifndef _SHA1_H
#define _SHA1_H

#include <glib.h>
#include "beecrypt_compat.h"

/*!\brief Holds all the parameters necessary for the SHA-1 algorithm.
 * \ingroup HASH_sha1_m
 */
typedef struct
{
	/*!\var h
	 */
	guint32 h[5];
	/*!\var data
	 */
	guint32 data[80];
	/*!\var length
	 * \brief Multi-precision integer counter for the bits that have been
	 *  processed so far.
	 */
	guint32 length[2];
	/*!\var offset
	 * \brief Offset into \a data; points to the place where new data will be
	 *  copied before it is processed.
	 */
	guint32 offset;
} sha1Param;

#ifdef __cplusplus
extern "C" {
#endif

/*!\fn void sha1Process(sha1Param* sp)
 * \brief This function performs the core of the SHA-1 hash algorithm; it
 *  processes a block of 64 bytes.
 * \param sp The hash function's parameter block.
 */

void sha1Process(sha1Param* sp);

/*!\fn int sha1Reset(sha1Param* sp)
 * \brief This function resets the parameter block so that it's ready for a
 *  new hash.
 * \param sp The hash function's parameter block.
 * \retval 0 on success. 
 */

int  sha1Reset  (sha1Param* sp);

/*!\fn int sha1Update(sha1Param* sp, const guchar* data, size_t size)
 * \brief This function should be used to pass successive blocks of data 
 *  to be hashed.
 * \param sp The hash function's parameter block.
 * \param data
 * \param size
 * \retval 0 on success.
 */

int  sha1Update (sha1Param* sp, const byte* data, size_t size);

/*!\fn int sha1Digest(sha1Param* sp, guchar* digest)
 * \brief This function finishes the current hash computation and copies
 *  the digest value into \a digest.
 * \param sp The hash function's parameter block.
 * \param digest The place to store the 20-byte digest.
 * \retval 0 on success.
 */

int  sha1Digest (sha1Param* sp, byte* digest);

#ifdef __cplusplus
}
#endif

#endif
