/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001 Virtual Unlimited B.V.
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

/*!\file sha1.c
 * \brief SHA-1 hash function, as specified by NIST FIPS 180-1.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup HASH_m HASH_sha1_m
 */

/* Modified from beecrypt by alexander larsson <alexl@redhat.com> */

#include "config.h"

#include "sha1.h"

static void
mpzero(size_t size, mpw* data)
{
        while (size--)
                *(data++) = 0;
}

static void
mpsetw(size_t size, mpw* xdata, mpw y)
{
        while (--size)
                *(xdata++) = 0;
        *(xdata++) = y;
}

static int
mpadd(size_t size, mpw* xdata, const mpw* ydata)
{
        register mpw load, temp;
        register int carry = 0;

        xdata += size-1;
        ydata += size-1;

        while (size--)
        {
                temp = *(ydata--);
                load = *xdata;
                temp = carry ? (load + temp + 1) : (load + temp);
                *(xdata--) = temp;
                carry = carry ? (load >= temp) : (load > temp);
        }
        return carry;
}

static void
mplshift(size_t size, mpw* data, size_t count)
{
        register size_t words = MP_BITS_TO_WORDS(count);

        if (words < size)
        {
                register short lbits = (short) (count & (MP_WBITS-1));

                /* first do the shifting, then do the moving */
                if (lbits)
                {
                        register mpw temp, carry = 0;
                        register short rbits = MP_WBITS - lbits;
                        register size_t i = size;

                        while (i > words)
                        {
                                temp = data[--i];
                                data[i] = (temp << lbits) | carry;
                                carry = (temp >> rbits);
                        }
                }
                if (words)
                {
                        mpmove(size-words, data, data+words);
                        mpzero(words, data+size-words);
                }
        }
        else
                mpzero(size, data);
}


static const guint32 k[4] = { 0x5a827999U, 0x6ed9eba1U, 0x8f1bbcdcU, 0xca62c1d6U };
static const guint32 hinit[5] = { 0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U };

int sha1Reset(register sha1Param* p)
{
	memcpy(p->h, hinit, 5 * sizeof(guint32));
	memset(p->data, 0, 80 * sizeof(guint32));
	mpzero(2, p->length);
	p->offset = 0;
	return 0;
}

#define SUBROUND1(a, b, c, d, e, w, k) \
	e = ROTL32(a, 5) + ((b&(c^d))^d) + e + w + k;	\
	b = ROTR32(b, 2)
#define SUBROUND2(a, b, c, d, e, w, k) \
	e = ROTL32(a, 5) + (b^c^d) + e + w + k;	\
	b = ROTR32(b, 2)
#define SUBROUND3(a, b, c, d, e, w, k) \
	e = ROTL32(a, 5) + (((b|c)&d)|(b&c)) + e + w + k;	\
	b = ROTR32(b, 2)
#define SUBROUND4(a, b, c, d, e, w, k) \
	e = ROTL32(a, 5) + (b^c^d) + e + w + k;	\
	b = ROTR32(b, 2)

#ifndef ASM_SHA1PROCESS
void sha1Process(sha1Param* sp)
{
	register guint32 a, b, c, d, e;
	register guint32 *w;
	register byte t;

	#if WORDS_BIGENDIAN
	w = sp->data + 16;
	#else
	w = sp->data;
	t = 16;
	while (t--)
	{
		register guint32 temp = GUINT32_SWAP_LE_BE(*w);
		*(w++) = temp;
	}
	#endif

	t = 64;
	while (t--)
	{
		register guint32 temp = w[-3] ^ w[-8] ^ w[-14] ^ w[-16];
		*(w++) = ROTL32(temp, 1);
	}

	w = sp->data;

	a = sp->h[0]; b = sp->h[1]; c = sp->h[2]; d = sp->h[3]; e = sp->h[4];

	SUBROUND1(a,b,c,d,e,w[ 0],k[0]);
	SUBROUND1(e,a,b,c,d,w[ 1],k[0]);
	SUBROUND1(d,e,a,b,c,w[ 2],k[0]);
	SUBROUND1(c,d,e,a,b,w[ 3],k[0]);
	SUBROUND1(b,c,d,e,a,w[ 4],k[0]);
	SUBROUND1(a,b,c,d,e,w[ 5],k[0]);
	SUBROUND1(e,a,b,c,d,w[ 6],k[0]);
	SUBROUND1(d,e,a,b,c,w[ 7],k[0]);
	SUBROUND1(c,d,e,a,b,w[ 8],k[0]);
	SUBROUND1(b,c,d,e,a,w[ 9],k[0]);
	SUBROUND1(a,b,c,d,e,w[10],k[0]);
	SUBROUND1(e,a,b,c,d,w[11],k[0]);
	SUBROUND1(d,e,a,b,c,w[12],k[0]);
	SUBROUND1(c,d,e,a,b,w[13],k[0]);
	SUBROUND1(b,c,d,e,a,w[14],k[0]);
	SUBROUND1(a,b,c,d,e,w[15],k[0]);
	SUBROUND1(e,a,b,c,d,w[16],k[0]);
	SUBROUND1(d,e,a,b,c,w[17],k[0]);
	SUBROUND1(c,d,e,a,b,w[18],k[0]);
	SUBROUND1(b,c,d,e,a,w[19],k[0]);

	SUBROUND2(a,b,c,d,e,w[20],k[1]);
	SUBROUND2(e,a,b,c,d,w[21],k[1]);
	SUBROUND2(d,e,a,b,c,w[22],k[1]);
	SUBROUND2(c,d,e,a,b,w[23],k[1]);
	SUBROUND2(b,c,d,e,a,w[24],k[1]);
	SUBROUND2(a,b,c,d,e,w[25],k[1]);
	SUBROUND2(e,a,b,c,d,w[26],k[1]);
	SUBROUND2(d,e,a,b,c,w[27],k[1]);
	SUBROUND2(c,d,e,a,b,w[28],k[1]);
	SUBROUND2(b,c,d,e,a,w[29],k[1]);
	SUBROUND2(a,b,c,d,e,w[30],k[1]);
	SUBROUND2(e,a,b,c,d,w[31],k[1]);
	SUBROUND2(d,e,a,b,c,w[32],k[1]);
	SUBROUND2(c,d,e,a,b,w[33],k[1]);
	SUBROUND2(b,c,d,e,a,w[34],k[1]);
	SUBROUND2(a,b,c,d,e,w[35],k[1]);
	SUBROUND2(e,a,b,c,d,w[36],k[1]);
	SUBROUND2(d,e,a,b,c,w[37],k[1]);
	SUBROUND2(c,d,e,a,b,w[38],k[1]);
	SUBROUND2(b,c,d,e,a,w[39],k[1]);

	SUBROUND3(a,b,c,d,e,w[40],k[2]);
	SUBROUND3(e,a,b,c,d,w[41],k[2]);
	SUBROUND3(d,e,a,b,c,w[42],k[2]);
	SUBROUND3(c,d,e,a,b,w[43],k[2]);
	SUBROUND3(b,c,d,e,a,w[44],k[2]);
	SUBROUND3(a,b,c,d,e,w[45],k[2]);
	SUBROUND3(e,a,b,c,d,w[46],k[2]);
	SUBROUND3(d,e,a,b,c,w[47],k[2]);
	SUBROUND3(c,d,e,a,b,w[48],k[2]);
	SUBROUND3(b,c,d,e,a,w[49],k[2]);
	SUBROUND3(a,b,c,d,e,w[50],k[2]);
	SUBROUND3(e,a,b,c,d,w[51],k[2]);
	SUBROUND3(d,e,a,b,c,w[52],k[2]);
	SUBROUND3(c,d,e,a,b,w[53],k[2]);
	SUBROUND3(b,c,d,e,a,w[54],k[2]);
	SUBROUND3(a,b,c,d,e,w[55],k[2]);
	SUBROUND3(e,a,b,c,d,w[56],k[2]);
	SUBROUND3(d,e,a,b,c,w[57],k[2]);
	SUBROUND3(c,d,e,a,b,w[58],k[2]);
	SUBROUND3(b,c,d,e,a,w[59],k[2]);

	SUBROUND4(a,b,c,d,e,w[60],k[3]);
	SUBROUND4(e,a,b,c,d,w[61],k[3]);
	SUBROUND4(d,e,a,b,c,w[62],k[3]);
	SUBROUND4(c,d,e,a,b,w[63],k[3]);
	SUBROUND4(b,c,d,e,a,w[64],k[3]);
	SUBROUND4(a,b,c,d,e,w[65],k[3]);
	SUBROUND4(e,a,b,c,d,w[66],k[3]);
	SUBROUND4(d,e,a,b,c,w[67],k[3]);
	SUBROUND4(c,d,e,a,b,w[68],k[3]);
	SUBROUND4(b,c,d,e,a,w[69],k[3]);
	SUBROUND4(a,b,c,d,e,w[70],k[3]);
	SUBROUND4(e,a,b,c,d,w[71],k[3]);
	SUBROUND4(d,e,a,b,c,w[72],k[3]);
	SUBROUND4(c,d,e,a,b,w[73],k[3]);
	SUBROUND4(b,c,d,e,a,w[74],k[3]);
	SUBROUND4(a,b,c,d,e,w[75],k[3]);
	SUBROUND4(e,a,b,c,d,w[76],k[3]);
	SUBROUND4(d,e,a,b,c,w[77],k[3]);
	SUBROUND4(c,d,e,a,b,w[78],k[3]);
	SUBROUND4(b,c,d,e,a,w[79],k[3]);

	sp->h[0] += a;
	sp->h[1] += b;
	sp->h[2] += c;
	sp->h[3] += d;
	sp->h[4] += e;
}
#endif

int sha1Update(sha1Param* sp, const byte* data, size_t size)
{
	register guint32 proclength;

	mpw add[2];
	mpsetw(2, add, size);
	mplshift(2, add, 3);
	mpadd(2, sp->length, add);

	while (size > 0)
	{
		proclength = ((sp->offset + size) > 64U) ? (64U - sp->offset) : size;
		memcpy(((byte *) sp->data) + sp->offset, data, proclength);
		size -= proclength;
		data += proclength;
		sp->offset += proclength;

		if (sp->offset == 64)
		{
			sha1Process(sp);
			sp->offset = 0;
		}
	}
	return 0;
}

static void sha1Finish(sha1Param* sp)
{
	register byte *ptr = ((byte *) sp->data) + sp->offset++;

	*(ptr++) = 0x80;

	if (sp->offset > 56)
	{
		while (sp->offset++ < 64)
			*(ptr++) = 0;

		sha1Process(sp);
		sp->offset = 0;
	}

	ptr = ((byte*) sp->data) + sp->offset;
	while (sp->offset++ < 56)
		*(ptr++) = 0;

	#if WORDS_BIGENDIAN
	memcpy(ptr, sp->length, 8);
	#else
	ptr[0] = (byte)(sp->length[0] >> 24);
	ptr[1] = (byte)(sp->length[0] >> 16);
	ptr[2] = (byte)(sp->length[0] >>  8);
	ptr[3] = (byte)(sp->length[0]      );
	ptr[4] = (byte)(sp->length[1] >> 24);
	ptr[5] = (byte)(sp->length[1] >> 16);
	ptr[6] = (byte)(sp->length[1] >>  8);
	ptr[7] = (byte)(sp->length[1]      );
	#endif

	sha1Process(sp);

	sp->offset = 0;
}

int sha1Digest(sha1Param* sp, byte* data)
{
	sha1Finish(sp);

	#if WORDS_BIGENDIAN
	memcpy(data, sp->h, 20);
	#else
	/* encode 5 integers big-endian style */
	data[ 0] = (byte)(sp->h[0] >> 24);
	data[ 1] = (byte)(sp->h[0] >> 16);
	data[ 2] = (byte)(sp->h[0] >>  8);
	data[ 3] = (byte)(sp->h[0] >>  0);
	data[ 4] = (byte)(sp->h[1] >> 24);
	data[ 5] = (byte)(sp->h[1] >> 16);
	data[ 6] = (byte)(sp->h[1] >>  8);
	data[ 7] = (byte)(sp->h[1] >>  0);
	data[ 8] = (byte)(sp->h[2] >> 24);
	data[ 9] = (byte)(sp->h[2] >> 16);
	data[10] = (byte)(sp->h[2] >>  8);
	data[11] = (byte)(sp->h[2] >>  0);
	data[12] = (byte)(sp->h[3] >> 24);
	data[13] = (byte)(sp->h[3] >> 16);
	data[14] = (byte)(sp->h[3] >>  8);
	data[15] = (byte)(sp->h[3] >>  0);
	data[16] = (byte)(sp->h[4] >> 24);
	data[17] = (byte)(sp->h[4] >> 16);
	data[18] = (byte)(sp->h[4] >>  8);
	data[19] = (byte)(sp->h[4] >>  0);
	#endif

	sha1Reset(sp);

	return 0;
}
