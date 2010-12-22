/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2010 Collabora Ltd

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#include "config.h"

#include "test-suite.h"

#include "gcr.h"
#include "gcr/gcr-internal.h"

#include "gck/gck-test.h"

#include "pkcs11/pkcs11n.h"

#include <glib.h>

static gpointer cert_data;
static gsize n_cert_data;

TESTING_SETUP (simple_certificate)
{
	/* Look for the config in the build directory */
	_gcr_set_pkcs11_config_dir (TEST_CONFIG_DIR);

	cert_data = testing_data_read ("der-certificate.crt", &n_cert_data);
	g_assert (cert_data);
}

TESTING_TEARDOWN (simple_certificate)
{
	g_free (cert_data);
	cert_data = NULL;
	n_cert_data = 0;
}

TESTING_TEST (simple_certificate_new)
{
	GcrCertificate *cert;
	gconstpointer der;
	gsize n_der;

	cert = gcr_simple_certificate_new (cert_data, n_cert_data);
	g_assert (GCR_IS_SIMPLE_CERTIFICATE (cert));

	der = gcr_certificate_get_der_data (cert, &n_der);
	g_assert (der);
	g_assert_cmpsize (n_der, ==, n_cert_data);
	g_assert (memcmp (der, cert_data, n_der) == 0);

	g_object_unref (cert);
}

TESTING_TEST (simple_certificate_new_static)
{
	GcrCertificate *cert;
	gconstpointer der;
	gsize n_der;

	cert = gcr_simple_certificate_new_static (cert_data, n_cert_data);
	g_assert (GCR_IS_SIMPLE_CERTIFICATE (cert));

	der = gcr_certificate_get_der_data (cert, &n_der);
	g_assert (der);
	g_assert_cmpsize (n_der, ==, n_cert_data);
	g_assert (der == cert_data); /* Must be same pointer */

	g_object_unref (cert);
}
