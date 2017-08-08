/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-communication.c: Communication with ssh-agent

   Copyright (C) 2017 Red Hat, Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   <http://www.gnu.org/licenses/>.

   Author: Jakub Jelen <jjelen@redhat.com>
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "pkcs11/pkcs11.h"
#include "gkd-ssh-agent-private.h"

/* 4 bytes: length of message
 * 1 byte: Operation ID (0x11 = SSH2_AGENTC_ADD_IDENTITY),
 * 4 bytes: length of key type (ssh-rsa)
 *                | message size ||OP|| key type size|| -------- ssh-rsa ---------*/
#define RSA_PAIR "\x00\x00\x03\xd3\x11\x00\x00\x00\x07\x73\x73\x68\x2d\x72\x73\x61" \
                 "\x00\x00\x01\x01\x00\xa0\x3e\x95\x2a\xa9\x21\x6b\x2e\xa9\x28\x74" \
                 "\x91\x8c\x01\x96\x59\xf1\x4f\x53\xcc\x5f\xb2\x2d\xa0\x9c\xec\x0f" \
                 "\xfc\x1d\x54\x1c\x3a\x33\xb7\x1d\xdc\xce\x13\xbe\xa7\x2f\xdf\x4e" \
                 "\x58\x42\x9d\x23\xf5\x8e\xc8\xe4\xad\x52\x19\x72\x7c\xda\x87\x67" \
                 "\xd4\x34\x51\x51\x81\x2e\x3e\x8d\x13\x81\xb6\xf6\xe0\x1e\xc4\xbb" \
                 "\xd9\x5d\x44\xeb\xe6\x68\x81\x5f\xa6\x04\x95\x96\x02\x1c\x34\x88" \
                 "\xfa\xe6\x43\x72\xaf\x9b\x7f\x03\xdc\xf0\x72\xa3\x96\x3b\xc8\xa3" \
                 "\xb9\x90\x81\xb6\x2e\x5a\x18\x2e\x3a\x2c\x27\x91\x78\xb3\x1d\xb1" \
                 "\x87\x4b\xb3\xdb\x05\xcd\xb6\x76\x35\x6f\x9c\x61\x7b\x6f\x95\x12" \
                 "\x4b\x26\xf4\xe0\x7e\x15\x76\x94\x91\x90\xb6\x7d\x0a" \
                 "\xd3\x36\x8f\x19\x18\x52\x50\x48\x57\x7c\x91\x48\x48\x7d\xb5\x03" \
                 "\x26\x69\x58\xb9\x9f\xaf\xbc\x73\x3e\x03\x72\xdc\xf6\xb1\xf2\x5b" \
                 "\x82\x0f\x69\x1c\xb1\x15\x07\x22\x46\x66\xfe\x65\x0a" \
                 "\x94\xda\xe4\x9d\x39\x70\x21\x83\x5e\xe5\xb2\x4b\x97\xfe\xaf\x32" \
                 "\x08\x8e\x47\xcb\x97\x83\x89\xc0\xb6\xdb\x6a\x14\x31\xd2\x53\xb5" \
                 "\x88\x30\x5f\x87\x50\x09\x4f\x13\x20\x25\xa1\xc5\xbd\xf1\xe1\x10" \
                 "\x95\xfa\x0e\xc3\xf7\xdf\xad\x90\x8b\xef\xfb\x00\x00\x00\x01\x23" \
                 "\x00\x00\x01\x01\x00\x9b\xaa\x82\x46\xb2\xed\x43\x8c\x69\xcf\x87" \
                 "\x2e\x4d\x7d\xe2\x83\x42\x2f\xcd\xbf\x38\x63\xf1\xcf\x39\x5a\x58" \
                 "\xab\xc4\xb8\x1b\x6b\xbd\x35\x8a\xb9\x3d\x37\xc0\x85\x27\x30\xb2" \
                 "\x81\x9f\xcb\xd9\xc9\xf8\x6b\x61\xcc\xf0\xab\x01\x80\x99\xc5\x5d" \
                 "\x8c\x50\x14\x7b\x0f\xc6\x85\xe8\x21\x93\xf3\x90\xbc\x75\xa9\x2b" \
                 "\x82\xb2\x60\x35\x9d\xff\x1e\x97\x6e\x13\x14\xf8\x1f\x4e\x99\x6f" \
                 "\x1f\x9d\xdb\x1e\xf3\xbb\x9f\xf5\x1f\xc5\x01\xa6\x3a\x2b\x72\x73" \
                 "\x29\x4a\x8c\xa2\x58\xe9\xce\x58\xca\xcb\xce\xaa\x92\x82\x1c\xd8" \
                 "\x57\x8b\x5e\x42\x79\x21\x0e\x63\x13\x0e\x03\xff\x2f\x7f\x64\xf6" \
                 "\x82\xe1\xfe\x0b\xc3\x1e\x4c\x50\x11\x3f\xc8\x8a\xba\xcc\xde\x24" \
                 "\xf7\xae\x96\x6c\x5e\x3b\x00\xfa\xf0\x0e\xac\x3a\xeb\xb1\xab\x8f" \
                 "\x3f\xdb\x80\xb3\x06\x91\x18\xe1\xf5\x3b\xec\x5d\x01\xcf\xd0\x1f" \
                 "\xaf\xe3\xd9\x12\xba\x7b\x0f\xee\x20\x29\x74\x57\xdc\x58\x75\xd4" \
                 "\xb0\xf4\xb4\xa4\x93\x48\x2b\x7b\x6b\x1d\x77\xbc\xf3\xfe\xbd\xad" \
                 "\xd6\x83\x05\x16\xca\xbe\x31\xa4\x39\x53\x29\xf3\xd3\x39\xb0\xa5" \
                 "\xef\xf0\xc9\x08\xd6\x63\x52\x0b\xcb\xfc\x1c\x21\xd3\xa9\x2f\x23" \
                 "\x92\x3d\x46\x8c\x4b\x00\x00\x00\x80\x15\x40\xcc\xa4\x83\xdf\x26" \
                 "\xbe\x55\x82\x85\x0f\x71\x3c\x19\xa8\x8b\x42\x80\xa5\x24\x5d\xad" \
                 "\xf5\x99\x33\xaf\x7c\xb2\x27\xae\x7b\x0b\x0b\xa0\x03\xfd\xae\x53" \
                 "\x6f\xf1\xdd\x83\x54\xde\xf2\xbd\x87\x2c\xa9\x4d\x7b\xa5\x6e\xdb" \
                 "\x5e\x89\xf4\x5c\x79\x22\xc3\xc4\x40\x50\xeb\xb7\xf4\x17\x78\x2f" \
                 "\x06\xa5\x3a\x65\x4d\x85\x98\x3e\xd8\x4d\x3b\xfc\xd8\x9b\xe5\xd1" \
                 "\x47\xb6\xe3\xda\x2e\xc5\x18\xce\x37\xd9\xd7\x9a\xbf\xba\xa9\xef" \
                 "\xf2\xaf\x9b\xc8\x46\x57\x11\x8c\xa9\x5f\x68\x8c\x43\x2f\xb5\x7a" \
                 "\x39\x38\x30\x79\xd5\x30\xa8\x2b\x98\x00\x00\x00\x81\x00\xcc\x50" \
                 "\xb1\x2c\x5f\xe4\x02\x85\x7d\xce\x77\xd8\x27\xc1\xf6\xee\xe2\x2b" \
                 "\x7b\x29\x83\x95\xf1\x5e\x3d\xe5\xa9\x75\x62\xc6\x84\xc9\x97\x26" \
                 "\x70\xf4\x0d\x28\x6a\xc6\x88\x7c\xa3\x0d\x35\xa3\x8f\xdc\x34\x4c" \
                 "\x78\x6b\xcc\x5d\x99\x7e\x45\xb0\xdf\xe3\x77\x48\x77\xd8\xa9\x1c" \
                 "\x74\xf9\xbc\xcc\x82\xdb\x44\x10\x96\xda\x00\x23\xaa\x04\x93\xcc" \
                 "\x98\xec\x26\x8b\x7d\x08\xf4\x82\xdc\x9a\xc4\x8c\xc8\xe9\x3e\x5b" \
                 "\xd6\xc7\x28\xf4\x38\x3a\x3c\x08\x56\xbb\xa2\xca\xfb\x05\xa0\xb7" \
                 "\xe1\x70\x59\xb4\x86\x2b\x29\x89\xb5\x82\x2a\x79\x61\x51\x00\x00" \
                 "\x00\x81\x00\xc8\xc7\xe6\x93\x90\x59\xe7\x54\x1b\xcf\x9c\xb0\x07" \
                 "\x80\x37\xcd\xdf\x65\xf4\x29\x1e\x4a\x93\x73\xd1\x7b\x47\x1d\x36" \
                 "\x87\x89\x1d\xbf\xd5\x1e\x02\xc2\xd1\x2b\xb3\x67\x07\x65\xf9\xbc" \
                 "\xcb\x74\x4c\x83\x68\xa8\x6d\x30\x68\x8f\xb5\xb9\x44\x86\xb8\xde" \
                 "\x4e\xfc\x02\x1e\x9c\x05\x3b\x23\x1b\xdf\x79\x58\x73\x51\x27\xf0" \
                 "\xbd\x83\x34\x38\xcb\xd0\x20\x12\xcd\x1a\x07\x6e\xf7\x0a" \
                 "\x92\x29\xff\x2f\xbf\x30\x2a\x69\x15\x4d\x8e\x6e\x17\x26\x7b\x43" \
                 "\xfe\x52\xd1\x83\x65\x19\x22\x8b\xd3\x6f\x97\x51\x11\x3f\x17\xfe" \
                 "\x05\xcc\xa4\x49\x8b\x00\x00\x00\x26\x70\x6b\x63\x73\x31\x31\x2f" \
                 "\x73\x73\x68\x2d\x73\x74\x6f\x72\x65\x2f\x66\x69\x78\x74\x75\x72" \
                 "\x65\x73\x2f\x69\x64\x5f\x72\x73\x61\x5f\x70\x6c\x61\x69\x6e"

#define DSA_PAIR "\x00\x00\x01\xf5\x11\x00\x00\x00\x07\x73\x73\x68\x2d\x64\x73\x73" \
                 "\x00\x00\x00\x81\x00\xc2\xc9\x98\xa3\xeb\x5e\x3c\x71\xbe\x86\xa7" \
                 "\x65\xda\xcd\x52\x6b\xfb\x3a\xdc\x7d\x29\x1b\x37\x53\x32\x79\x1e" \
                 "\x61\x0a" \
                 "\x00\x02\x4e\xa7\x27\xd4\x3e\x11\x86\xe7\xfb\xf6\xe5\x9e\xee\x5b" \
                 "\xf2\x62\xe3\xf2\x5c\xd7\x9d\x7d\xd7\xb4\x88\x53\xfb\x15\xff\x64" \
                 "\xd5\x3f\x62\xde\xd8\x72\x62\x3b\x35\xb1\xc7\x70\xa5\xba\xb1\x9c" \
                 "\x05\x67\x98\xde\x12\x36\xff\xef\x7c\x55\xcf\xa7\xac\x34\x10\x33" \
                 "\x6a\x98\x03\xb0\x83\xe3\xea\xc2\xe7\xbb\x8e\xe8\x8f\x54\x9c\x8f" \
                 "\x05\xcb\x12\x3d\x96\x4a\x4c\xe3\x03\x09\x2f\xf6\x7d\x58\x9b\x14" \
                 "\x25\xe0\xb3\x00\x00\x00\x15\x00\xe5\xba\x9e\x03\x42\x83\xa7\x78" \
                 "\x0a" \
                 "\x7f\x86\x1d\x0b\x44\x6c\xd5\x6d\x66\x94\x5d\x00\x00\x00\x80\x3f" \
                 "\x62\xe1\x10\x7f\xb3\x50\x26\x2b\x8b\x4c\x62\xdf\x69\x7d\x6c\xc9" \
                 "\xe5\xa8\x30\x81\x77\x0d\xb3\x38\xc6\xde\x1b\x65\xc3\x46\xde\x34" \
                 "\x5b\x83\x9b\x88\x4d\x7e\x3c\xf3\x69\xfc\x20\xc5\xb9\x8a\xce\x8c" \
                 "\x3e\x2c\xec\x29\x78\xb3\xf5\x3e\x8a\x8a\x78\x0c\xab\x0f\x70\xbc" \
                 "\x1b\x76\xbd\xc2\xa1\x61\x3a\x84\x4b\x8e\x74\x7d\x23\x93\x37\x2f" \
                 "\xb7\xc9\x19\xe5\x89\xad\x9b\x73\xa2\xa8\x45\xb6\x01\x18\xbc\xad" \
                 "\x4c\x15\x27\xdf\x9b\x45\xb9\x1f\x45\xea\xcd\xac\x37\x87\xfc\xf4" \
                 "\x33\xc0\x25\x9f\xec\xbc\xe9\xf6\x53\xd3\x35\x58\xc2\x0e\xdb\x00" \
                 "\x00\x00\x80\x0d\x5b\xe1\xed\xb8\x95\x95\x99\xf5\xd1\x44\x32\x75" \
                 "\x82\x83\x0a" \
                 "\xf8\x65\xe2\xc4\x3b\xc1\x2c\x16\xc5\x48\x37\xfb\xe2\x46\x08\x9e" \
                 "\xdd\xef\x50\x19\xb8\x30\xaa\x6b\x1d\xb9\x82\xdb\xb4\xcb\x47\x29" \
                 "\x9b\xe8\x83\x87\xd4\x43\x69\x61\x3d\xcc\x7d\xf6\x49\xba\xc4\x13" \
                 "\xaa\xa6\x49\x28\xf6\xda\xe6\x7c\x0b\xbc\xf3\xfd\x97\x33\x7a\xd1" \
                 "\xb2\x40\xb6\xa8\x96\x52\xca\x9f\xc0\x71\x21\xe8\x9c\x7e\xaa\x83" \
                 "\x20\x82\x6f\x22\xea\x88\x09\x24\xed\xb3\x0e\x59\x22\xe5\x3c\x1f" \
                 "\xd6\x29\x4d\xfa\xd8\xa7\x1d\xd3\x8b\xff\x60\xa6\x3c\xf4\x4c\x80" \
                 "\x00\x00\x00\x15\x00\xb2\x9f\x51\x2e\xb5\xc6\xa1\x53\x39\x8e\x5f" \
                 "\x1b\x5f\xab\x2f\x09\x4f\x1a\xf2\xfd\x00\x00\x00\x26\x70\x6b\x63" \
                 "\x73\x31\x31\x2f\x73\x73\x68\x2d\x73\x74\x6f\x72\x65\x2f\x66\x69" \
                 "\x78\x74\x75\x72\x65\x73\x2f\x69\x64\x5f\x64\x73\x61\x5f\x70\x6c" \
                 "\x61\x69\x6e"

#define ECDSA_PAIR "\x00\x00\x00\xba\x11\x00\x00\x00\x13\x65\x63\x64\x73\x61\x2d\x73" \
                   "\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35\x36\x00\x00\x00\x08" \
                   "\x6e\x69\x73\x74\x70\x32\x35\x36\x00\x00\x00\x41\x04\xa8\xeb\x59" \
                   "\xa5\xb6\x01\xd8\x39\xac\x23\x73\xc3\x19\x74\x40\xad\x2d\xd7\x2d" \
                   "\xfe\x06\x84\xe4\x2b\xe1\x5c\x57\x24\x72\x2f\xec\xbf\x0e\xc3\x67" \
                   "\x56\x95\xce\xfd\x9d\x1d\x86\x4a\x74\xb6\x42\xc5\xc6\x45\x59\x01" \
                   "\x38\x03\xc7\xe5\x97\x5f\xbd\x52\xeb\x23\x5c\xcb\x9c\x00\x00\x00" \
                   "\x21\x00\xc6\x16\xa3\x20\xe3\x83\x9b\xc6\x94\x6e\x43\x2e\x8e\x84" \
                   "\x9a\x7c\xd7\x2b\x83\x86\x7e\x70\x3e\xd8\x6a\xcb\xf6\x9d\xf1\x7e" \
                   "\xfb\xbe\x00\x00\x00\x28\x70\x6b\x63\x73\x31\x31\x2f\x73\x73\x68" \
                   "\x2d\x73\x74\x6f\x72\x65\x2f\x66\x69\x78\x74\x75\x72\x65\x73\x2f" \
                   "\x69\x64\x5f\x65\x63\x64\x73\x61\x5f\x70\x6c\x61\x69\x6e"


typedef struct {
	unsigned char *rsakey;
	gsize rsakey_len;
	unsigned char *dsakey;
	gsize dsakey_len;
	unsigned char *ecdsakey;
	gsize ecdsakey_len;
} Test;

static void
setup (Test *test, gconstpointer unused)
{
	test->rsakey = (unsigned char *) RSA_PAIR;
	test->rsakey_len = sizeof(RSA_PAIR);
	test->dsakey = (unsigned char *) DSA_PAIR;
	test->dsakey_len = sizeof(DSA_PAIR);
	test->ecdsakey = (unsigned char *) ECDSA_PAIR;
	test->ecdsakey_len = sizeof(ECDSA_PAIR);
}

static void
teardown (Test *test, gconstpointer unused)
{
}

/* Reads private key from SSH client
 * Writes the public key
 * Reads the written public key */
static void
test_read_write_rsa (Test *test, gconstpointer unused)
{
	GckAttributes *priv_attrs, *pub_attrs, *new_pub_attrs;
	const GckAttribute *priv_attr, *pub_attr, *new_pub_attr;
	GckBuilder priv, pub, new_pub;
	EggBuffer buffer, resp;
	gsize offset = 5; /* skipping message number (4B length, 1B message) */
	gchar *stype;
	gboolean ret;
	gulong value, algo;

	/* Prepare intercepted message from  ssh-add  */
	egg_buffer_init_static (&buffer, test->rsakey, test->rsakey_len);
	egg_buffer_init (&resp, 128);

	/* check the key type */
	ret = egg_buffer_get_string (&buffer, 5, &offset, &stype, (EggBufferAllocator)g_realloc);
	g_assert (ret);
	g_assert_cmpstr (stype, ==, "ssh-rsa");

	/* parse the key to PKCS11 structures */
	gck_builder_init (&pub);
	gck_builder_init (&priv);
	ret = gkd_ssh_agent_proto_read_pair_rsa (&buffer, &offset, &priv, &pub);
	g_assert (ret);

	/* Finish */
	pub_attrs = gck_builder_end (&pub);
	g_assert (pub_attrs);
	priv_attrs = gck_builder_end (&priv);
	g_assert (priv_attrs);

	/* private looks reasonable */
	gck_attributes_find_ulong (priv_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PRIVATE_KEY);
	gck_attributes_find_ulong (priv_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_RSA);
	/* public looks reasonable */
	gck_attributes_find_ulong (pub_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PUBLIC_KEY);
	gck_attributes_find_ulong (pub_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_RSA);
	/* public exponent should be same */
	priv_attr = gck_attributes_find (priv_attrs, CKA_PUBLIC_EXPONENT);
	pub_attr = gck_attributes_find (pub_attrs, CKA_PUBLIC_EXPONENT);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	/* try to write the public key */
	ret = gkd_ssh_agent_proto_write_public (&resp, pub_attrs);
	g_assert (ret);
	g_assert (egg_buffer_length(&resp) != 0);

	/* Read the written public key */
	gck_builder_init (&new_pub);
	offset = 0; /* in this case we do not have message length and operation */
	ret = gkd_ssh_agent_proto_read_public (&resp, &offset, &new_pub, &algo);
	g_assert (ret);
	g_assert_cmpuint (algo, ==, CKK_RSA);
	new_pub_attrs = gck_builder_end (&new_pub);
	g_assert (new_pub_attrs);

	/* check that the parameters in old and new public key match */
	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_PUBLIC_EXPONENT);
	pub_attr = gck_attributes_find (pub_attrs, CKA_PUBLIC_EXPONENT);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_MODULUS);
	pub_attr = gck_attributes_find (pub_attrs, CKA_MODULUS);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	/* cleanup */
	g_free (stype);
	gck_attributes_unref (priv_attrs);
	gck_attributes_unref (pub_attrs);
	gck_attributes_unref (new_pub_attrs);
	egg_buffer_uninit (&buffer);
	egg_buffer_uninit (&resp);
}

static void
test_read_write_dsa (Test *test, gconstpointer unused)
{
	GckAttributes *priv_attrs, *pub_attrs, *new_pub_attrs;
	const GckAttribute *priv_attr, *pub_attr, *new_pub_attr;
	GckBuilder priv, pub, new_pub;
	EggBuffer buffer, resp;
	gsize offset = 5; /* skipping message number (4B length, 1B message) */
	gchar *stype;
	gboolean ret;
	gulong value, algo;

	/* Prepare intercepted message from  ssh-add  */
	egg_buffer_init_static (&buffer, test->dsakey, test->dsakey_len);
	egg_buffer_init (&resp, 128);

	/* check the key type */
	ret = egg_buffer_get_string (&buffer, 5, &offset, &stype, (EggBufferAllocator)g_realloc);
	g_assert (ret);
	g_assert_cmpstr (stype, ==, "ssh-dss");

	/* parse the key to PKCS11 structures */
	gck_builder_init (&pub);
	gck_builder_init (&priv);
	ret = gkd_ssh_agent_proto_read_pair_dsa (&buffer, &offset, &priv, &pub);
	g_assert (ret);

	/* Finish */
	pub_attrs = gck_builder_end (&pub);
	g_assert (pub_attrs);
	priv_attrs = gck_builder_end (&priv);
	g_assert (priv_attrs);

	/* private looks reasonable */
	gck_attributes_find_ulong (priv_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PRIVATE_KEY);
	gck_attributes_find_ulong (priv_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_DSA);
	/* public looks reasonable */
	gck_attributes_find_ulong (pub_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PUBLIC_KEY);
	gck_attributes_find_ulong (pub_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_DSA);
	/* public parts should be same */
	priv_attr = gck_attributes_find (priv_attrs, CKA_PRIME);
	pub_attr = gck_attributes_find (pub_attrs, CKA_PRIME);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	priv_attr = gck_attributes_find (priv_attrs, CKA_SUBPRIME);
	pub_attr = gck_attributes_find (pub_attrs, CKA_SUBPRIME);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	priv_attr = gck_attributes_find (priv_attrs, CKA_BASE);
	pub_attr = gck_attributes_find (pub_attrs, CKA_BASE);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	/* try to write the public key */
	ret = gkd_ssh_agent_proto_write_public (&resp, pub_attrs);
	g_assert (ret);
	g_assert (egg_buffer_length(&resp) != 0);

	/* Read the written public key */
	gck_builder_init (&new_pub);
	offset = 0; /* in this case we do not have message length and operation */
	ret = gkd_ssh_agent_proto_read_public (&resp, &offset, &new_pub, &algo);
	g_assert (ret);
	g_assert_cmpuint (algo, ==, CKK_DSA);
	new_pub_attrs = gck_builder_end (&new_pub);
	g_assert (new_pub_attrs);

	/* check that the parameters in old and new public key match */
	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_PRIME);
	pub_attr = gck_attributes_find (pub_attrs, CKA_PRIME);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_SUBPRIME);
	pub_attr = gck_attributes_find (pub_attrs, CKA_SUBPRIME);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_BASE);
	pub_attr = gck_attributes_find (pub_attrs, CKA_BASE);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	/* cleanup */
	g_free (stype);
	gck_attributes_unref (priv_attrs);
	gck_attributes_unref (pub_attrs);
	gck_attributes_unref (new_pub_attrs);
	egg_buffer_uninit (&buffer);
	egg_buffer_uninit (&resp);
}

static void
test_read_write_ecdsa (Test *test, gconstpointer unused)
{
	GckAttributes *priv_attrs, *pub_attrs, *new_pub_attrs;
	const GckAttribute *priv_attr, *pub_attr, *new_pub_attr;
	GckBuilder priv, pub, new_pub;
	EggBuffer buffer, resp;
	gsize offset = 5; /* skipping message number (4B length, 1B message) */
	gchar *stype;
	gboolean ret;
	gulong value, algo;

	/* Prepare intercepted message from  ssh-add  */
	egg_buffer_init_static (&buffer, test->ecdsakey, test->ecdsakey_len);
	egg_buffer_init (&resp, 128);

	/* check the key type */
	ret = egg_buffer_get_string (&buffer, 5, &offset, &stype, (EggBufferAllocator)g_realloc);
	g_assert (ret);
	g_assert_cmpstr (stype, ==, "ecdsa-sha2-nistp256");

	/* parse the key to PKCS11 structures */
	gck_builder_init (&pub);
	gck_builder_init (&priv);
	ret = gkd_ssh_agent_proto_read_pair_ecdsa (&buffer, &offset, &priv, &pub);
	g_assert (ret);

	/* Finish */
	pub_attrs = gck_builder_end (&pub);
	g_assert (pub_attrs);
	priv_attrs = gck_builder_end (&priv);
	g_assert (priv_attrs);

	/* private looks reasonable */
	gck_attributes_find_ulong (priv_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PRIVATE_KEY);
	gck_attributes_find_ulong (priv_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_ECDSA);
	/* public looks reasonable */
	gck_attributes_find_ulong (pub_attrs, CKA_CLASS, &value);
	g_assert_cmpuint (value, ==, CKO_PUBLIC_KEY);
	gck_attributes_find_ulong (pub_attrs, CKA_KEY_TYPE, &value);
	g_assert_cmpuint (value, ==, CKK_ECDSA);
	/* public parts should be same */
	priv_attr = gck_attributes_find (priv_attrs, CKA_EC_PARAMS);
	pub_attr = gck_attributes_find (pub_attrs, CKA_EC_PARAMS);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	priv_attr = gck_attributes_find (priv_attrs, CKA_EC_POINT);
	pub_attr = gck_attributes_find (pub_attrs, CKA_EC_POINT);
	g_assert_cmpmem (priv_attr->value, priv_attr->length, pub_attr->value, pub_attr->length);

	/* try to write the public key */
	ret = gkd_ssh_agent_proto_write_public (&resp, pub_attrs);
	g_assert (ret);
	g_assert (egg_buffer_length(&resp) != 0);

	/* Read the written public key */
	gck_builder_init (&new_pub);
	offset = 0; /* in this case we do not have message length and operation */
	ret = gkd_ssh_agent_proto_read_public (&resp, &offset, &new_pub, &algo);
	g_assert (ret);
	g_assert_cmpuint (algo, ==, CKK_ECDSA);
	new_pub_attrs = gck_builder_end (&new_pub);
	g_assert (new_pub_attrs);

	/* check that the parameters in old and new public key match */
	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_EC_PARAMS);
	pub_attr = gck_attributes_find (pub_attrs, CKA_EC_PARAMS);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	new_pub_attr = gck_attributes_find (new_pub_attrs, CKA_EC_POINT);
	pub_attr = gck_attributes_find (pub_attrs, CKA_EC_POINT);
	g_assert_cmpmem (new_pub_attr->value, new_pub_attr->length, pub_attr->value, pub_attr->length);

	/* cleanup */
	g_free (stype);
	gck_attributes_unref (priv_attrs);
	gck_attributes_unref (pub_attrs);
	egg_buffer_uninit (&buffer);
	egg_buffer_uninit (&resp);
}

/*	gkd_ssh_agent_proto_write_signature_rsa (); XXX next test */

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/daemon/ssh-agent/communication/rsa_pair", Test, NULL, setup, test_read_write_rsa, teardown);
	g_test_add ("/daemon/ssh-agent/communication/dsa_pair", Test, NULL, setup, test_read_write_dsa, teardown);
	g_test_add ("/daemon/ssh-agent/communication/ecdsa_pair", Test, NULL, setup, test_read_write_ecdsa, teardown);

	return g_test_run ();
}
