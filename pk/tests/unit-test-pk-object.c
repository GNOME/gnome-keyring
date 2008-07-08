/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-object.c: Test a object

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

#include "common/gkr-location.h"

#include "pk/gkr-pk-cert.h"
#include "pk/gkr-pk-index.h"
#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-object-manager.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-der.h"

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

static GkrPkObjectManager *manager = NULL;
static GkrPkObject *object_1 = NULL;

void unit_setup_object (void)
{
	/* Our own object manager */
	manager = gkr_pk_object_manager_instance_for_client (1239);
	object_1 = g_object_new (GKR_TYPE_PK_CERT, "location", 0, "manager", manager, NULL);
}

void unit_test_object_label (CuTest* cu)
{
	CK_ATTRIBUTE attr;
	const gchar *label;
	GQuark loc;
	
	/* Should always return a default label */
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned for empty object", label != NULL);
	g_printerr ("EMPTY LABEL: %s\n", label);
	
	/* The next priority should be the location based label */
	loc = gkr_location_from_child (GKR_LOCATION_VOLUME_FILE, "test-object.pk");
	g_object_set (object_1, "location", loc, NULL);
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after location label", label != NULL);
	CuAssert (cu, "wrong label returned after location label", strcmp (label, "test-object.pk") == 0);
	g_printerr ("LOCATION LABEL: %s\n", label);
	
	/* Should return the original label by default (parsed) */
	g_object_set (object_1, "orig-label", "Orig Label", NULL);
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after orig label", label != NULL);
	CuAssert (cu, "wrong label returned after orig label", strcmp (label, "Orig Label") == 0);
	g_printerr ("ORIG LABEL: %s\n", label);
	
	/* After setting a label in index, should return that */
	gkr_pk_object_index_set_string (object_1, GKR_PK_INDEX_LABEL, "Index Label");
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after index label", label != NULL);
	CuAssert (cu, "wrong label returned after index label", strcmp (label, "Index Label") == 0);
	g_printerr ("INDEX LABEL: %s\n", label);
	
	/* Should be able to set the label via pkcs11 */
	attr.pValue = "Pkcs11 Label";
	attr.ulValueLen = strlen (attr.pValue);
	attr.type = CKA_LABEL;
	gkr_pk_object_set_attribute (object_1, &attr);
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after pkcs11 label", label != NULL);
	CuAssert (cu, "wrong label returned after pkcs11 label", strcmp (label, "Pkcs11 Label") == 0);
	g_printerr ("PKCS11 LABEL: %s\n", label);
	
	/* Should be able to set the label via properties */
	g_object_set (object_1, "label", "Property Label", NULL);
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after property label", label != NULL);
	CuAssert (cu, "wrong label returned after property label", strcmp (label, "Property Label") == 0);
	g_printerr ("PROPERTY LABEL: %s\n", label);

	/* Should be able to set the label directly */
	gkr_pk_object_set_label(object_1, "Direct Label");
	label = gkr_pk_object_get_label (object_1);
	CuAssert (cu, "no label returned after direct label", label != NULL);
	CuAssert (cu, "wrong label returned after direct label", strcmp (label, "Direct Label") == 0);
	g_printerr ("DIRECT LABEL: %s\n", label);
}

#include "check-attribute.c"
		 
void unit_test_object_static (CuTest *cu)
{
	gkr_pk_object_set_label (object_1, "The Label");
	
	CHECK_BOOL_ATTRIBUTE (cu, object_1, CKA_PRIVATE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, object_1, CKA_TOKEN, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, object_1, CKA_MODIFIABLE, CK_TRUE);
	CHECK_BYTE_ATTRIBUTE (cu, object_1, CKA_LABEL, "The Label", strlen ("The Label"));
}

