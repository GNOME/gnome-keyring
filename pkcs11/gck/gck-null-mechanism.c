/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gck-null-key.h"
#include "gck-null-mechanism.h"
#include "gck-session.h"
#include "gck-transaction.h"
#include "gck-util.h"

#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

static gboolean
retrieve_length (GckSession *session, GckObject *wrapped, gsize *length)
{
	CK_ATTRIBUTE attr;

	attr.type = CKA_VALUE;
	attr.pValue = NULL;
	attr.ulValueLen = 0;

	if (gck_object_get_attribute (wrapped, session, &attr) != CKR_OK)
		return FALSE;

	*length = attr.ulValueLen;
	return TRUE;
}

static gpointer
retrieve_value (GckSession *session, GckObject *wrapped, gsize *n_value)
{
	CK_ATTRIBUTE attr;

	if (!retrieve_length (session, wrapped, n_value))
		return NULL;

	attr.type = CKA_VALUE;
	attr.pValue = egg_secure_alloc (*n_value);
	attr.ulValueLen = *n_value;

	if (gck_object_get_attribute (wrapped, session, &attr) != CKR_OK) {
		egg_secure_free (attr.pValue);
		return NULL;
	}

	return attr.pValue;
}

CK_RV
gck_null_mechanism_wrap (GckSession *session, CK_MECHANISM_PTR mech,
                        GckObject *wrapper, GckObject *wrapped,
                        CK_BYTE_PTR output, CK_ULONG_PTR n_output)
{
	GckNullKey *key;
	gpointer value;
	gsize n_value;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (mech, CKR_GENERAL_ERROR);
	g_return_val_if_fail (mech->mechanism == CKM_G_NULL, CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_OBJECT (wrapped), CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_output, CKR_GENERAL_ERROR);

	if (!GCK_IS_NULL_KEY (wrapper))
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	key = GCK_NULL_KEY (wrapper);

	/* They just want the length */
	if (!output) {
		if (!retrieve_length (session, wrapped, &n_value))
			return CKR_KEY_NOT_WRAPPABLE;
		*n_output = n_value;
		return CKR_OK;
	}

	if (mech->ulParameterLen)
		return CKR_MECHANISM_PARAM_INVALID;

	value = retrieve_value (session, wrapped, &n_value);
	if (value == NULL)
		return CKR_KEY_NOT_WRAPPABLE;

	rv = gck_util_return_data (output, n_output, value, n_value);
	egg_secure_free (value);
	return rv;
}

CK_RV
gck_null_mechanism_unwrap (GckSession *session, CK_MECHANISM_PTR mech,
                          GckObject *wrapper, CK_VOID_PTR input, CK_ULONG n_input,
                          CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs,
                          GckObject **unwrapped)
{
	CK_ATTRIBUTE attr;
	GArray *array;
	GckNullKey *key;
	GckTransaction *transaction;

	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (mech, CKR_GENERAL_ERROR);
	g_return_val_if_fail (mech->mechanism == CKM_G_NULL, CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_OBJECT (wrapper), CKR_GENERAL_ERROR);

	if (!GCK_IS_NULL_KEY (wrapper))
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	key = GCK_NULL_KEY (wrapper);

	if (mech->ulParameterLen)
		return CKR_MECHANISM_PARAM_INVALID;

	/* Now setup the attributes with our new value */
	array = g_array_new (FALSE, FALSE, sizeof (CK_ATTRIBUTE));

	/* Prepend the value */
	attr.type = CKA_VALUE;
	attr.pValue = input;
	attr.ulValueLen = n_input;
	g_array_append_val (array, attr);

	/* Add the remainder of the attributes */
	g_array_append_vals (array, attrs, n_attrs);

	transaction = gck_transaction_new ();

	/* Now create an object with these attributes */
	*unwrapped = gck_session_create_object_for_attributes (session, transaction,
	                                                       (CK_ATTRIBUTE_PTR)array->data, array->len);

	g_array_free (array, TRUE);

	return gck_transaction_complete_and_unref (transaction);
}
