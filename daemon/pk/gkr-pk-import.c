/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-import.c - Object used to track an import

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

#include "gkr-pk-import.h"
#include "gkr-pk-object.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-session.h"
#include "gkr-pk-storage.h"
#include "gkr-pk-util.h"

#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-parser.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib-object.h>
#include <glib/gi18n.h>

/* -------------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_IMPORT_MANAGER,
	PROP_IMPORT_STORAGE,
	PROP_IMPORT_TOKEN,
	PROP_IMPORT_LABEL
};

typedef struct _GkrPkImportPrivate GkrPkImportPrivate;

struct _GkrPkImportPrivate {
	GError *error;

	gchar *raw_data;
	gsize n_raw_data;
};

G_DEFINE_TYPE (GkrPkImport, gkr_pk_import, GKR_TYPE_PK_OBJECT);

#define GKR_PK_IMPORT_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PK_IMPORT, GkrPkImportPrivate))

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void
object_disappeared (gpointer data, GObject *exobject)
{
	GkrPkImport *import = GKR_PK_IMPORT (data);
	import->import_objects = g_slist_remove (import->import_objects, exobject);
}

static const gchar*
prepare_ask_title (GQuark type)
{
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Import private key");
	else if (type == GKR_PKIX_CERTIFICATE)
		return _("Import certificate");
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return _("Import public key");
	else 
		return _("Import");
}

static const gchar*
prepare_ask_primary (GQuark type)
{
	if (type == GKR_PKIX_PRIVATE_KEY)
		return _("Enter password to unlock the private key");
	else if (type == GKR_PKIX_CERTIFICATE)
		return _("Enter password to unlock the certificate");
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return _("Enter password to unlock the public key");
	else 
		return _("Enter password to unlock");
}

static gchar*
prepare_ask_secondary (GQuark type, const gchar *label)
{
	if (type == GKR_PKIX_PRIVATE_KEY)
		return g_strdup_printf (_("The system wants to import the private key '%s', but it is locked"), label);
	else if (type == GKR_PKIX_CERTIFICATE)
		return g_strdup_printf (_("The system wants to import the certificate '%s', but it is locked"), label);
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return g_strdup_printf (_("The system wants to import the public key '%s', but it is locked"), label);
	else 
		return g_strdup_printf (_("The system wants to import '%s', but it is locked"), label);
}

static gboolean
parser_ask_password (GkrPkixParser *parser, GQuark loc, gkrconstid digest, 
                     GQuark type, const gchar *label, gint *state, gchar **result,
                     GkrPkImport *import)
{
	GkrAskRequest *ask;
	gchar *secondary;
	gboolean ret = TRUE;
	GkrPkIndex *index;
	guint flags;
	
	g_return_val_if_fail (GKR_IS_PK_IMPORT (import), FALSE);
	g_return_val_if_fail (digest != NULL, FALSE);
	g_return_val_if_fail (state != NULL, FALSE);
	g_return_val_if_fail (result != NULL, FALSE);
	
	/*  
	 * Certain encryption mechanisms (eg: PKCS12) behave differently with
	 * a null and a blank password. And some crypto libraries use a null 
	 * password and some use a blank password. 
	 * 
	 * The net effect is that if the user enters a blank password we 
	 * also need to try a null password.
	 */
	
	#define LAST_WAS_BLANK 1
	if (*state == LAST_WAS_BLANK) {
		*result = NULL;
		*state = 0;
		return TRUE;
	}
	
	if (!label || !label[0]) 
		label = import->import_label;
		
	/* Build up the prompt */
	flags = GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_CANCEL_BUTTONS;
	ask = gkr_ask_request_new (prepare_ask_title (type), 
	                           prepare_ask_primary (type), flags);

	secondary = prepare_ask_secondary (type, label); 
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);

	/* 
	 * TODO: We should be able to prompt for a location to import this 
	 * object to.
	 */
		
	index = gkr_pk_storage_index (import->import_storage, loc);
		
	/* Prompt the user */
	gkr_ask_daemon_process (ask);

	/* If the user denied ... */
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		ret = FALSE;
		
	/* User cancelled or failure */
	} else if (ask->response < GKR_ASK_RESPONSE_ALLOW) {
		ret = FALSE;
			
	/* Successful response */
	} else {
		*result = egg_secure_strdup (ask->typed_password);
		if (*result && strlen (*result) == 0)
			*state = LAST_WAS_BLANK;
	}
	
	g_object_unref (ask);
	return ret;
}

static gboolean 
process_parsed (GkrPkImport *import, GQuark location, gkrconstid digest,
                GQuark type, const gchar *property, gpointer value)
{
	GkrPkImportPrivate *pv = GKR_PK_IMPORT_GET_PRIVATE (import);
 	GkrPkObject *object;
 	gboolean created = FALSE;
 	
 	g_return_val_if_fail (type != 0, FALSE);
	g_return_val_if_fail (import->import_storage, FALSE);
	g_return_val_if_fail (import->import_manager, FALSE);
	
	/* Already had an error? Skip all the rest */
	if (pv->error)
		return FALSE;

	object = gkr_pk_manager_find_by_digest (import->import_manager, digest);
	if (!object) {
		created = TRUE;
		object = g_object_new (gkr_pk_object_get_object_type (type), 
		                       "manager", import->import_manager, 
		                       "location", location, "digest", digest, NULL);
	}
 	
	/* Setup the sexp, probably a key on this object */
	g_return_val_if_fail (object, FALSE);
	g_object_set (object, property, value, NULL);
	
	/* Apply the import label to the object if it has none */
	if (!gkr_pk_object_has_label (object) && import->import_label)
		g_object_set (object, "label", import->import_label, NULL);
	
	import->import_objects = g_slist_prepend (import->import_objects, object);
	g_object_weak_ref (G_OBJECT (object), object_disappeared, import);

	if (created) {
		gkr_pk_storage_store (import->import_storage, object, &pv->error);
		g_object_unref (object);
	}
	
	return TRUE;
}

static gboolean
parser_parsed_sexp (GkrPkixParser *parser, GQuark location, gkrconstid digest,
                    GQuark type, gcry_sexp_t sexp, GkrPkImport *import)
{
	return process_parsed (import, location, digest, type, "gcrypt-sexp", sexp);
}

static gboolean
parser_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                    GQuark type, ASN1_TYPE asn1, GkrPkImport *import)
{
	return process_parsed (import, location, digest, type, "asn1-tree", asn1);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_import_init (GkrPkImport *import)
{

}

static CK_RV
gkr_pk_import_get_attribute (GkrPkObject* obj, CK_ATTRIBUTE_PTR attr)
{
	GkrPkImportPrivate *pv = GKR_PK_IMPORT_GET_PRIVATE (obj);
	GkrPkImport *import = GKR_PK_IMPORT (obj);
	GArray *imported;
	CK_OBJECT_HANDLE handle;
	GSList *l;
	gsize n_data;
	
	g_assert (!attr->pValue);
	
	switch (attr->type)
	{
	/* An array of integers, handles of objects imported */
	case CKA_GNOME_IMPORT_OBJECTS:
		imported = g_array_new (0, 1, sizeof (CK_OBJECT_HANDLE));
		for (l = import->import_objects; l; l = g_slist_next (l)) {
			/* Make sure it's all valid */
			g_return_val_if_fail (GKR_IS_PK_OBJECT (l->data), CKR_GENERAL_ERROR);
			handle = GKR_PK_OBJECT (l->data)->handle;
			g_return_val_if_fail (handle != 0, CKR_GENERAL_ERROR);
			g_array_append_val (imported, handle);
		}
		
		n_data = imported->len * sizeof (CK_OBJECT_HANDLE);
		gkr_pk_attribute_take_data (attr, g_array_free (imported, FALSE), n_data);
		return CKR_OK;
		
	/* The actual data imported */
	case CKA_VALUE:
		gkr_pk_attribute_set_data (attr, pv->raw_data, pv->n_raw_data);
		return CKR_OK;
	
	/* Imported to token or session */
	case CKA_GNOME_IMPORT_TOKEN:
		gkr_pk_attribute_set_boolean (attr, import->import_token);
		return CKR_OK;
		
	/* Import label */
	case CKA_GNOME_IMPORT_LABEL:
		gkr_pk_attribute_set_string (attr, import->import_label);
		return CKR_OK;
		
	default:
		break;
	};

	return GKR_PK_OBJECT_CLASS (gkr_pk_import_parent_class)->get_attribute (obj, attr);
}

static void
gkr_pk_import_get_property (GObject *obj, guint prop_id, GValue *value, 
                            GParamSpec *pspec)
{
	GkrPkImport *import = GKR_PK_IMPORT (obj);

	switch (prop_id) {
	case PROP_IMPORT_MANAGER:
		g_value_set_object (value, import->import_manager);
		break;
	case PROP_IMPORT_STORAGE:
		g_value_set_object (value, import->import_storage);
		break;
	case PROP_IMPORT_TOKEN:
		g_value_set_boolean (value, import->import_token);
		break;
	case PROP_IMPORT_LABEL:
		g_value_set_string (value, import->import_label);
		break;
	}
}

static void
gkr_pk_import_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkImport *import = GKR_PK_IMPORT (obj);
	
	switch (prop_id) {
	case PROP_IMPORT_MANAGER:
		g_assert (!import->import_manager);
		import->import_manager = g_value_get_object (value);
		g_return_if_fail (import->import_manager);
		g_object_add_weak_pointer (G_OBJECT (import->import_manager),
		                           (gpointer*)&(import->import_manager));
		break; 
		
	case PROP_IMPORT_STORAGE:
		g_assert (!import->import_storage);
		import->import_storage = g_value_get_object (value);
		g_return_if_fail (import->import_storage);
		g_object_add_weak_pointer (G_OBJECT (import->import_storage),
		                           (gpointer*)&(import->import_storage));
		break;
		
	case PROP_IMPORT_TOKEN:
		import->import_token = g_value_get_boolean (value);
		break;
		
	case PROP_IMPORT_LABEL:
		g_assert (!import->import_label);
		import->import_label = g_value_dup_string (value);
		break;
	};
}

static void
gkr_pk_import_finalize (GObject *obj)
{
	GkrPkImportPrivate *pv = GKR_PK_IMPORT_GET_PRIVATE (obj);
	GkrPkImport *import = GKR_PK_IMPORT (obj);
	GSList *l;
	
	/* Free our imported data */
	g_free (pv->raw_data);
	pv->raw_data = NULL;
	pv->n_raw_data = 0;
	
	/* Free up any errors straggling */
	g_clear_error (&pv->error);
	
	/* Remove all weak references to objects */
	for (l = import->import_objects; l; l = g_slist_next (l)) {
		g_return_if_fail (GKR_IS_PK_OBJECT (l->data));
		g_object_weak_unref (G_OBJECT (l->data), object_disappeared, import);
	}
	
	g_slist_free (import->import_objects);
	import->import_objects = NULL;
	
	/* Remove the weak reference to storage */
	if (import->import_storage)
		g_object_remove_weak_pointer (G_OBJECT (import->import_storage), 
		                              (gpointer*)&(import->import_storage));
	import->import_storage = NULL;

	/* Remove the weak reference to manager */
	if (import->import_manager)
		g_object_remove_weak_pointer (G_OBJECT (import->import_manager), 
		                              (gpointer*)&(import->import_manager));
	import->import_manager = NULL;
	
	/* The import label */
	g_free (import->import_label);
	import->import_label = NULL;
	
	G_OBJECT_CLASS (gkr_pk_import_parent_class)->finalize (obj);
}

static void
gkr_pk_import_class_init (GkrPkImportClass *klass)
{
	GObjectClass *gobject_class;
	GkrPkObjectClass *parent_class;
	
	gobject_class = (GObjectClass*)klass;

	gkr_pk_import_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = GKR_PK_OBJECT_CLASS (klass);
	parent_class->get_attribute = gkr_pk_import_get_attribute;
	
	gobject_class->finalize = gkr_pk_import_finalize;
	gobject_class->get_property = gkr_pk_import_get_property;
	gobject_class->set_property = gkr_pk_import_set_property;
	
	g_object_class_install_property (gobject_class, PROP_IMPORT_MANAGER, 
		g_param_spec_object ("import-manager", "Import Manager", "Object Manager to Import To",
		                     GKR_TYPE_PK_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_IMPORT_STORAGE,
		g_param_spec_object ("import-storage", "Import Storage", "Storage to Import To",
		                     GKR_TYPE_PK_STORAGE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_IMPORT_TOKEN,
		g_param_spec_boolean ("import-token", "Import Token", "Whether to import to token or session",
		                      FALSE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_IMPORT_LABEL,
		g_param_spec_string ("import-label", "Import Label", "Label for prompts and imported objects without labels",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_type_class_add_private (gobject_class, sizeof (GkrPkImportPrivate));
}

CK_RV
gkr_pk_import_create (GkrPkManager* manager, GkrPkSession *session, 
                      GArray* array, GkrPkObject **object)
{
	CK_ATTRIBUTE_PTR vattr, lattr;
 	CK_BBOOL import_token, token;
 	GError *err = NULL;
 	gchar *label;
 	CK_RV ret;
 	
	g_return_val_if_fail (GKR_IS_PK_MANAGER (manager), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GKR_IS_PK_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (array, CKR_GENERAL_ERROR);
	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
	
	*object = NULL;
	
	/* Cannot create a import object on a token */
	if (gkr_pk_attributes_boolean (array, CKA_TOKEN, &token) && token)
		return CKR_TEMPLATE_INCONSISTENT;

	/* Must specify where the import goes */
	if (!gkr_pk_attributes_boolean (array, CKA_GNOME_IMPORT_TOKEN, &import_token))
		return CKR_TEMPLATE_INCOMPLETE;
	
	/* Must have an import value */
	vattr = gkr_pk_attributes_find (array, CKA_VALUE);
	if (!vattr)
		return CKR_TEMPLATE_INCOMPLETE;
	
	lattr = gkr_pk_attributes_find (array, CKA_GNOME_IMPORT_LABEL);
	if (lattr)
		label = g_strndup (lattr->pValue, lattr->ulValueLen);
	else
		label = NULL;

	/* 
	 * Figure out where we store objects to, note this is not where this 'import'
	 * object will actually end up being stored.
	 */

	/* Create ourselves an import object */
	*object = g_object_new (GKR_TYPE_PK_IMPORT, 
	                        "manager", manager,
	                        "import-storage", import_token ? gkr_pk_storage_get_default () : session->storage,
	                        "import-manager", import_token ? gkr_pk_manager_for_token() : session->manager,
	                        "import-token", import_token,
	                        "import-label", label,
	                        NULL);
	
	g_free (label);
	
	/* Perform the actual import */
	if (!gkr_pk_import_perform (GKR_PK_IMPORT (*object), vattr->pValue, 
	                            vattr->ulValueLen, &err)) {
		
		g_object_unref (*object);
		*object = NULL;

		if (err->domain == GKR_PKIX_PARSE_ERROR) {
			if (err->code == GKR_PKIX_CANCELLED)
				ret = CKR_FUNCTION_CANCELED;
			else
				ret = CKR_DATA_INVALID;
		} else {
			ret = CKR_FUNCTION_FAILED;
		}

		g_message ("couldn't import data: %s", err && err->message ? err->message : "");
		g_clear_error (&err);
		
		return ret;
	}
	
	/* All the attributes that we used up */
	gkr_pk_attributes_consume (array, CKA_VALUE, CKA_GNOME_IMPORT_TOKEN, 
	                           CKA_GNOME_IMPORT_LABEL, G_MAXULONG);
	
	return CKR_OK;
}

GSList*
gkr_pk_import_get_objects (GkrPkImport *import)
{
 	g_return_val_if_fail (GKR_IS_PK_IMPORT (import), NULL);	
	return g_slist_copy (import->import_objects);
}

gboolean
gkr_pk_import_perform (GkrPkImport *import, const guchar *data, gsize n_data, GError **err)
{
	GkrPkImportPrivate *pv = GKR_PK_IMPORT_GET_PRIVATE (import);
 	GkrPkixParser *parser;
 	gboolean ret;
	
 	g_return_val_if_fail (GKR_IS_PK_IMPORT (import), FALSE);
 	
	parser = gkr_pkix_parser_new (TRUE);
	g_signal_connect (parser, "parsed-asn1", G_CALLBACK (parser_parsed_asn1), import);
	g_signal_connect (parser, "parsed-sexp", G_CALLBACK (parser_parsed_sexp), import);
 	g_signal_connect (parser, "ask-password", G_CALLBACK (parser_ask_password), import);

	ret = gkr_pkix_parser_parse (parser, 0, data, n_data, err);
	g_object_unref (parser);
	
	if (!ret)
		return FALSE;

	/* Check for import errors */
	if (pv->error) {
		g_propagate_error (err, pv->error);
		pv->error = NULL;
		return FALSE;
	}
	
	pv->raw_data = g_memdup (data, n_data);
	pv->n_raw_data = n_data;

	return TRUE;	
}
