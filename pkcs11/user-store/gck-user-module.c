/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gck-user-module.h"
#include "gck-user-private-key.h"
#include "gck-user-public-key.h"
#include "gck-user-storage.h"
#include "gck-user-store.h"

#include "gck/gck-certificate.h"
#include "gck/gck-data-asn1.h"
#include "gck/gck-login.h"
#include "gck/gck-manager.h"
#include "gck/gck-transaction.h"
#include "gck/gck-util.h"

#include <string.h>

struct _GckUserModule {
	GckModule parent;
	GckUserStorage *storage;
	gchar *directory;
	GHashTable *unlocked_apps;
	CK_TOKEN_INFO token_info;
};

static const CK_SLOT_INFO user_module_slot_info = {
	"User Keys",
	"Gnome Keyring",
	CKF_TOKEN_PRESENT,
	{ 0, 0 },
	{ 0, 0 }
};

static const CK_TOKEN_INFO user_module_token_info = {
	"User Keys",
	"Gnome Keyring",
	"1.0",
	"1:USER:DEFAULT", /* Unique serial number for manufacturer */
	CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	1024,
	1,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	{ 0, 0 },
	{ 0, 0 },
	""
};

#define UNUSED_VALUE (GUINT_TO_POINTER (1))

G_DEFINE_TYPE (GckUserModule, gck_user_module, GCK_TYPE_MODULE);

/* -----------------------------------------------------------------------------
 * ACTUAL PKCS#11 Module Implementation 
 */

/* Include all the module entry points */
#include "gck/gck-module-ep.h"
GCK_DEFINE_MODULE (gck_user_module, GCK_TYPE_USER_MODULE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static const CK_SLOT_INFO* 
gck_user_module_real_get_slot_info (GckModule *base)
{
	return &user_module_slot_info;
}

static const CK_TOKEN_INFO*
gck_user_module_real_get_token_info (GckModule *base)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	
	/* Update the info with current info */
	self->token_info.flags = gck_user_storage_token_flags (self->storage);
	
	return &self->token_info;
}

static void 
gck_user_module_real_parse_argument (GckModule *base, const gchar *name, const gchar *value)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	if (g_str_equal (name, "directory")) {
		g_free (self->directory);
		self->directory = g_strdup (value);
	}
}

static CK_RV
gck_user_module_real_refresh_token (GckModule *base)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	gck_user_storage_refresh (self->storage);
	return CKR_OK;
}

static void 
gck_user_module_real_store_token_object (GckModule *base, GckTransaction *transaction, GckObject *object)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	gck_user_storage_create (self->storage, transaction, object);
}

static void 
gck_user_module_real_remove_token_object (GckModule *base, GckTransaction *transaction, GckObject *object)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	gck_user_storage_destroy (self->storage, transaction, object);
}

static CK_RV 
gck_user_module_real_login_change (GckModule *base, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR old_pin, 
                                   CK_ULONG n_old_pin, CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	GckLogin *old_login, *new_login;
	GckTransaction *transaction;
	CK_RV rv;
	
	/* 
	 * Remember this doesn't affect the currently logged in user. Logged in 
	 * sessions will remain logged in, and vice versa.
	 */ 
	
	old_login = gck_login_new (old_pin, n_old_pin);
	new_login = gck_login_new (new_pin, n_new_pin);
	
	transaction = gck_transaction_new ();
	
	gck_user_storage_relock (self->storage, transaction, old_login, new_login);
	
	g_object_unref (old_login);
	g_object_unref (new_login);
	
	gck_transaction_complete (transaction);
	rv = gck_transaction_get_result (transaction);
	g_object_unref (transaction);
	
	return rv;
}

static CK_RV 
gck_user_module_real_login_user (GckModule *base, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	GckLogin *login;
	CK_RV rv;

	/* See if this application has logged in */
	if (g_hash_table_lookup (self->unlocked_apps, &slot_id))
		return CKR_USER_ALREADY_LOGGED_IN;

	login = gck_user_storage_get_login (self->storage);
	
	/* No application is logged in */
	if (g_hash_table_size (self->unlocked_apps) == 0) {

		g_return_val_if_fail (login == NULL, CKR_GENERAL_ERROR);

		/* So actually unlock the store */
		login = gck_login_new (pin, n_pin);
		rv = gck_user_storage_unlock (self->storage, login);
		g_object_unref (login);
		
	/* An application is already logged in */
	} else {
		
		g_return_val_if_fail (login != NULL, CKR_GENERAL_ERROR);
		
		/* Compare our pin to the one used originally */
		if (!gck_login_equals (login, pin, n_pin))
			rv = CKR_PIN_INCORRECT;
		else
			rv = CKR_OK;
	}

	/* Note that this application logged in */
	if (rv == CKR_OK) {
		g_hash_table_insert (self->unlocked_apps, gck_util_ulong_alloc (slot_id), UNUSED_VALUE);
		rv = GCK_MODULE_CLASS (gck_user_module_parent_class)->login_user (base, slot_id, pin, n_pin);
	}
	
	return rv;
}

static CK_RV 
gck_user_module_real_login_so (GckModule *base, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	
	/* See if this application has unlocked, in which case we can't login */
	if (g_hash_table_lookup (self->unlocked_apps, &slot_id))
		return CKR_USER_ALREADY_LOGGED_IN;
	
	/* Note that for an SO login, we don't actually unlock, and pin is always blank */
	if (n_pin != 0)
		return CKR_PIN_INCORRECT;

	return GCK_MODULE_CLASS (gck_user_module_parent_class)->login_so (base, slot_id, pin, n_pin);
}

static CK_RV 
gck_user_module_real_logout_user (GckModule *base, CK_SLOT_ID slot_id)
{
	GckUserModule *self = GCK_USER_MODULE (base);
	CK_RV rv;
	
	if (!g_hash_table_remove (self->unlocked_apps, &slot_id))
		return CKR_USER_NOT_LOGGED_IN;
	
	if (g_hash_table_size (self->unlocked_apps) > 0)
		return CKR_OK;
	
	rv = gck_user_storage_lock (self->storage);
	if (rv == CKR_OK)
		rv = GCK_MODULE_CLASS (gck_user_module_parent_class)->logout_user (base, slot_id);
	
	return rv;
}

static GObject* 
gck_user_module_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckUserModule *self = GCK_USER_MODULE (G_OBJECT_CLASS (gck_user_module_parent_class)->constructor(type, n_props, props));	
	g_return_val_if_fail (self, NULL);	

	if (!self->directory)
		self->directory = g_build_filename (g_get_home_dir (), ".gnome2", "keyrings", NULL);
	self->storage = gck_user_storage_new (GCK_MODULE (self), self->directory);

	return G_OBJECT (self);
}

static void
gck_user_module_init (GckUserModule *self)
{
	self->unlocked_apps = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, gck_util_ulong_free, NULL);
	
	/* Our default token info, updated as module runs */
	memcpy (&self->token_info, &user_module_token_info, sizeof (CK_TOKEN_INFO));
	
	/* For creating stored keys */
	gck_module_register_factory (GCK_MODULE (self), GCK_FACTORY_USER_PRIVATE_KEY);
	gck_module_register_factory (GCK_MODULE (self), GCK_FACTORY_USER_PUBLIC_KEY);
}

static void
gck_user_module_dispose (GObject *obj)
{
	GckUserModule *self = GCK_USER_MODULE (obj);
	
	if (self->storage)
		g_object_unref (self->storage);
	self->storage = NULL;
	
	g_hash_table_remove_all (self->unlocked_apps);
    
	G_OBJECT_CLASS (gck_user_module_parent_class)->dispose (obj);
}

static void
gck_user_module_finalize (GObject *obj)
{
	GckUserModule *self = GCK_USER_MODULE (obj);
	
	g_assert (self->storage == NULL);
	
	g_assert (self->unlocked_apps);
	g_hash_table_destroy (self->unlocked_apps);
	self->unlocked_apps = NULL;
	
	g_free (self->directory);
	self->directory = NULL;

	G_OBJECT_CLASS (gck_user_module_parent_class)->finalize (obj);
}

static void
gck_user_module_class_init (GckUserModuleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckModuleClass *module_class = GCK_MODULE_CLASS (klass);
	
	gobject_class->constructor = gck_user_module_constructor;
	gobject_class->dispose = gck_user_module_dispose;
	gobject_class->finalize = gck_user_module_finalize;
	
	module_class->get_slot_info = gck_user_module_real_get_slot_info;
	module_class->get_token_info = gck_user_module_real_get_token_info;
	module_class->parse_argument = gck_user_module_real_parse_argument;
	module_class->refresh_token = gck_user_module_real_refresh_token;
	module_class->store_token_object = gck_user_module_real_store_token_object;
	module_class->remove_token_object = gck_user_module_real_remove_token_object;
	module_class->login_user = gck_user_module_real_login_user;
	module_class->login_so = gck_user_module_real_login_so;
	module_class->logout_user = gck_user_module_real_logout_user;
	module_class->login_change = gck_user_module_real_login_change;
}

/* ----------------------------------------------------------------------------
 * PUBLIC
 */

CK_FUNCTION_LIST_PTR
gck_user_store_get_functions (void)
{
	gck_crypto_initialize ();
	return gck_user_module_function_list;
}
