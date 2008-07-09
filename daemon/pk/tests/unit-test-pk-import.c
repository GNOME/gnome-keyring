/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-import.c: Test an import object

   Copyright (C) 2007 Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "run-auto-test.h"

#include "pk/gkr-pk-cert.h"
#include "pk/gkr-pk-import.h"
#include "pk/gkr-pk-index.h"
#include "pk/gkr-pk-manager.h"
#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-session.h"
#include "pk/gkr-pk-util.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include <glib.h>
#include <memory.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */
static GkrPkSession *session = NULL;
static GkrPkManager *manager = NULL;
static GkrPkImport *import = NULL;


void unit_setup_import (void)
{
	/* Our own object manager */
	session = gkr_pk_session_new_for_client (1238);
	manager = session->manager;
	
	/* A fake default storage so tests below go through */
	gkr_pk_storage_register (session->storage, TRUE);
}

void unit_test_import_create_invalid (CuTest *cu)
{
	GArray *attrs;
	GkrPkObject *object;
	CK_RV ret;
	CK_ATTRIBUTE attr;

	attrs = gkr_pk_attributes_new ();
	memset (&attr, 0, sizeof (attr));
	
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_GNOME_IMPORT);
	gkr_pk_attributes_append (attrs, &attr);

	/* Try to create as with a set of invalid attributes */
	ret = gkr_pk_object_create (session, attrs, &object);
	CuAssert (cu, "Certificate creation succeeded wrongly", ret == CKR_TEMPLATE_INCOMPLETE);

	gkr_pk_attributes_free (attrs);
	attrs = gkr_pk_attributes_new ();
	
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_GNOME_IMPORT);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_GNOME_IMPORT_TOKEN;
	gkr_pk_attribute_set_boolean (&attr, CK_FALSE);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_TOKEN; 
	gkr_pk_attribute_set_boolean (&attr, CK_TRUE);
	gkr_pk_attributes_append (attrs, &attr);
	
	/* Shouldn't be able to create an import on the token */
	ret = gkr_pk_object_create (session, attrs, &object);
	CuAssert (cu, "Certificate creation succeeded wrongly", ret == CKR_TEMPLATE_INCONSISTENT);
}

#include "check-attribute.c"

void unit_test_create_import (CuTest* cu)
{
	GkrPkObject *object;
	guchar *data;
	gsize n_data;
	CK_RV ret;
	GArray *attrs;
	CK_ATTRIBUTE attr;
	
	if (!g_file_get_contents ("test-data/certificate-1.crt", (gchar**)&data, &n_data, NULL))
		g_error ("couldn't read certificate-1.crt");

	attrs = gkr_pk_attributes_new ();
	memset (&attr, 0, sizeof (attr));
		
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_GNOME_IMPORT);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_TOKEN; 
	gkr_pk_attribute_set_boolean (&attr, CK_FALSE);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_VALUE;
	gkr_pk_attribute_take_data (&attr, data, n_data);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_GNOME_IMPORT_TOKEN;
	gkr_pk_attribute_set_boolean (&attr, CK_FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_GNOME_IMPORT_LABEL;
	gkr_pk_attribute_set_string (&attr, "Test Import Label");
	gkr_pk_attributes_append (attrs, &attr);
	
	/* Now try with a proper set of attributes */
	ret = gkr_pk_object_create (session, attrs, &object);
	CuAssert (cu, "Certificate creation failed", ret == CKR_OK);
	CuAssert (cu, "Returned invalid object", GKR_IS_PK_IMPORT (object));
	
	import = GKR_PK_IMPORT (object);
	
	/* Check that the data is correct */
	CHECK_BYTE_ATTRIBUTE (cu, import, CKA_VALUE, data, n_data);
	CHECK_BOOL_ATTRIBUTE (cu, import, CKA_GNOME_IMPORT_TOKEN, CK_FALSE);
	CHECK_STRING_ATTRIBUTE (cu, import, CKA_GNOME_IMPORT_LABEL, "Test Import Label");
	
	gkr_pk_attributes_free (attrs);
}

void unit_test_import_objects (CuTest *cu)
{
	GkrPkObject *object;
	GSList *objects;
	
	/* Check that the object has the right stuff */
	objects = gkr_pk_import_get_objects (import);
	
	CuAssert (cu, "Should have imported one object", g_slist_length (objects) == 1);
	CuAssert (cu, "Should have imported an object", GKR_IS_PK_OBJECT (objects->data));
	object = GKR_PK_OBJECT (objects->data);
	CuAssert (cu, "Should have imported a certificate", GKR_IS_PK_CERT (object));

	/* Check that the properties work */
	CHECK_BYTE_ATTRIBUTE (cu, import, CKA_GNOME_IMPORT_OBJECTS, &object->handle, sizeof (object->handle));
	
	/* Check that the label is set correctly */
	CHECK_STRING_ATTRIBUTE (cu, object, CKA_LABEL, "Test Import Label");
	CuAssert (cu, "Should have setup label", strcmp (gkr_pk_object_get_label (object), "Test Import Label") == 0); 
}

