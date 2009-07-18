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

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11i.h"

#include "gck-attributes.h"
#include "gck-certificate.h"
#include "gck-factory.h"
#include "gck-manager.h"
#include "gck-module.h"
#include "gck-private-key.h"
#include "gck-public-key.h"
#include "gck-session.h"
#include "gck-timer.h"
#include "gck-transaction.h"
#include "gck-util.h"

enum {
	PROP_0,
	PROP_MANAGER,
	PROP_WRITE_PROTECTED,
	PROP_INITIALIZE_ARGS,
	PROP_MUTEX
};

struct _GckModulePrivate {
	GckManager *token_manager; 
	GHashTable *virtual_slots_by_id;        /* Various slot partitions by their ID */
	GHashTable *sessions_by_handle;         /* Mapping of handle to all open sessions */
	gint handle_counter;                    /* Constantly incrementing counter for handles and the like */
	GArray *factories;                      /* Various registered object factories */
	gboolean factories_sorted;              /* Whether we need to sort the object factories */
	GMutex *mutex;                          /* The mutex controlling entry to this module */
};

typedef struct _VirtualSlot {
	CK_SLOT_ID slot_id;
	GckManager *session_manager;
	GList *sessions;
	CK_USER_TYPE logged_in;
} VirtualSlot;

/* Our slot identifier is 1 */
#define GCK_SLOT_ID  1

G_DEFINE_TYPE (GckModule, gck_module, G_TYPE_OBJECT);

/* These info blocks are used unless derived class overrides */

static const CK_INFO default_module_info = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	"Gnome Keyring",
	CKF_GNOME_APPARTMENTS,
	"Gnome Keyring Module",
	{ 1, 1 },
};

static const CK_SLOT_INFO default_slot_info = {
	"Unnamed Slot",
	"Gnome Keyring",
	CKF_TOKEN_PRESENT,
	{ 0, 0 },
	{ 0, 0 }
};

static const CK_TOKEN_INFO default_token_info = {
	"Unnamed Token",
	"Gnome Keyring",
	"1.0",
	"1",
	CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED,
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

typedef struct _MechanismAndInfo {
	CK_MECHANISM_TYPE mechanism;
	CK_MECHANISM_INFO info;
} MechanismAndInfo;

static const MechanismAndInfo mechanism_list[] = {
	/*  
	 * CKM_RSA_PKCS
	 * For RSA, min and max are the minimum and maximum modulus in bits
	 */
	{ CKM_RSA_PKCS, { 256, 32768, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY } },

	/* 
	 * CKM_RSA_X509
	 * For RSA, min and max are the minimum and maximum modulus in bits
	 */
	{ CKM_RSA_X_509, { 256, 32768, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY } },
	
	/*
	 * CKM_DSA
	 * For DSA, min and max are the minimum and maximum modulus in bits
	 */
	{ CKM_DSA, { 512, 1024, CKF_SIGN | CKF_VERIFY } }
};

/* Hidden function that you should not use */
GMutex* _gck_module_get_scary_mutex_that_you_should_not_touch (GckModule *self);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static gint
sort_factory_by_n_attrs (gconstpointer a, gconstpointer b)
{
	const GckFactoryInfo *fa = a;
	const GckFactoryInfo *fb = b;
	
	g_assert (a);
	g_assert (b);
	
	/* Note we're sorting in reverse order */
	if (fa->n_attrs < fb->n_attrs)
		return 1;
	return (fa->n_attrs == fb->n_attrs) ? 0 : -1;
}

static void
extend_space_string (CK_UTF8CHAR_PTR string, gsize length)
{
	CK_UTF8CHAR_PTR at;
	
	/* Find a null pointer in the string */
	at = memchr (string, 0, length);
	g_assert (at != NULL && at < string + length);
	for (; at < string + length; ++at) 
		*at = ' ';
}

static void
virtual_slot_free (gpointer data)
{
	VirtualSlot *slot;
	GList *l;
	
	g_assert (data != NULL);
	slot = (VirtualSlot*)data;
	
	g_return_if_fail (GCK_IS_MANAGER (slot->session_manager));
	
	/* Unreference all the sessions */
	for (l = slot->sessions; l; l = g_list_next (l)) {
		
		/* Some sanity checks to make sure things have remained as expected */
		g_return_if_fail (GCK_IS_SESSION (l->data));
		g_return_if_fail (gck_session_get_slot_id (l->data) == slot->slot_id);
		g_return_if_fail (gck_session_get_manager (l->data) == slot->session_manager);
		g_return_if_fail (gck_session_get_logged_in (l->data) == slot->logged_in);
		
		g_object_unref (l->data);
	}
	
	g_list_free (slot->sessions);
	g_object_unref (slot->session_manager);
	
	g_slice_free (VirtualSlot, slot);
}

static VirtualSlot*
virtual_slot_new (GckModuleClass *klass, CK_SLOT_ID slot_id)
{
	VirtualSlot *slot;

	slot = g_slice_new0 (VirtualSlot);
	slot->session_manager = g_object_new (GCK_TYPE_MANAGER, "for-token", FALSE, NULL);
	slot->logged_in = CKU_NONE;
	slot->sessions = NULL;
	slot->slot_id = slot_id;
	
	return slot;
}

static VirtualSlot*
lookup_virtual_slot (GckModule *self, CK_SLOT_ID slot_id)
{
	g_assert (GCK_IS_MODULE (self));
	return g_hash_table_lookup (self->pv->virtual_slots_by_id, &slot_id);
}

static void
register_virtual_slot (GckModule *self, VirtualSlot *slot)
{
	g_assert (slot);
	g_assert (GCK_IS_MODULE (self));
	g_assert (!g_hash_table_lookup (self->pv->virtual_slots_by_id, &(slot->slot_id)));
	
	g_hash_table_insert (self->pv->virtual_slots_by_id, 
	                            gck_util_ulong_alloc (slot->slot_id), slot);
}

static void
unregister_virtual_slot (GckModule *self, VirtualSlot *slot)
{
	g_assert (slot);
	g_assert (GCK_IS_MODULE (self));
	
	if (!g_hash_table_remove (self->pv->virtual_slots_by_id, &(slot->slot_id)))
		g_assert_not_reached ();
}

static void
mark_login_virtual_slot (GckModule *self, VirtualSlot *slot, CK_USER_TYPE user)
{
	GList *l;

	g_assert (slot);
	g_assert (GCK_IS_MODULE (self));
	
	/* Mark all sessions in the partition as logged in */
	for (l = slot->sessions; l; l = g_list_next (l)) 
		gck_session_set_logged_in (l->data, user);
	slot->logged_in = user;
}

static void
parse_argument (GckModule *self, char *arg)
{
	gchar *value;

	g_assert (GCK_IS_MODULE (self));

	value = arg + strcspn (arg, ":=");
	if (!*value)
		value = NULL;
	else 
		*(value++) = 0;

	g_strstrip (arg);
	g_strstrip (value);
	
	g_return_if_fail (GCK_MODULE_GET_CLASS (self)->parse_argument);
	GCK_MODULE_GET_CLASS (self)->parse_argument (self, arg, value);
}

static void
parse_arguments (GckModule *self, const gchar *string)
{
	gchar quote = '\0';
	gchar *src, *dup, *at, *arg;
	
	g_assert (GCK_IS_MODULE (self));
	
	if (!string)
		return;
	
	src = dup = g_strdup (string);

	arg = at = src;
	for (src = dup; *src; src++) {
		
		/* Matching quote */
		if (quote == *src) {
			quote = '\0';
			
		/* Inside of quotes */
		} else if (quote != '\0') {
			if (*src == '\\') {
				*at++ = *src++;
				if (!*src) {
					g_warning ("couldn't parse module argument string");
					goto done;
				}
				if (*src != quote) 
					*at++ = '\\';
			}
			*at++ = *src;
			
		/* Space, not inside of quotes */
		} else if (g_ascii_isspace(*src)) {
			*at = 0;
			parse_argument (self, arg);
			arg = at;
			
		/* Other character outside of quotes */
		} else {
			switch (*src) {
			case '\'':
			case '"':
				quote = *src;
				break;
			case '\\':
				*at++ = *src++;
				if (!*src) {
					g_warning ("couldn't parse module argument string");
					goto done;
				}
				/* fall through */
			default:
				*at++ = *src;
				break;
			}
		}
	}

	
	if (at != arg) {
		*at = 0;
		parse_argument (self, arg);
	}
	
done:
	g_free (dup);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static const CK_SLOT_INFO* 
gck_module_real_get_slot_info (GckModule *self)
{
	return &default_slot_info;
}

static const CK_TOKEN_INFO*
gck_module_real_get_token_info (GckModule *self)
{
	return &default_token_info;
}

static void 
gck_module_real_parse_argument (GckModule *self, const gchar *name, const gchar *value)
{
	/* Derived classes should do something interesting */
}

static CK_RV
gck_module_real_refresh_token (GckModule *self)
{
	/* Derived classes should do something interesting */
	return CKR_OK;
}

static void
gck_module_real_store_token_object (GckModule *self, GckTransaction *transaction, GckObject *object)
{
	/* Derived classes should do something interesting */
	gck_transaction_fail (transaction, CKR_FUNCTION_NOT_SUPPORTED);
}

static void
gck_module_real_remove_token_object (GckModule *self, GckTransaction *transaction, GckObject *object)
{
	/* Derived classes should do something interesting */
	gck_transaction_fail (transaction, CKR_FUNCTION_NOT_SUPPORTED);
}

static CK_RV
gck_module_real_login_change (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR old_pin, 
                              CK_ULONG n_old_pin, CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
gck_module_real_login_user (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	VirtualSlot *slot;
	
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	mark_login_virtual_slot (self, slot, CKU_USER);
	return CKR_OK;
}

static CK_RV
gck_module_real_login_so (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	VirtualSlot *slot;
	
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	mark_login_virtual_slot (self, slot, CKU_SO);
	return CKR_OK;
}

static CK_RV
gck_module_real_logout_any (GckModule *self, CK_SLOT_ID slot_id)
{
	VirtualSlot *slot;

	/* Calculate the partition identifier */
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	mark_login_virtual_slot (self, slot, CKU_NONE);
	return CKR_OK;
}

static GObject* 
gck_module_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckModule *self = GCK_MODULE (G_OBJECT_CLASS (gck_module_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	


	
	return G_OBJECT (self);
}

static void
gck_module_init (GckModule *self)
{
	gck_timer_initialize ();

	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_MODULE, GckModulePrivate);
	self->pv->token_manager = g_object_new (GCK_TYPE_MANAGER, "for-token", TRUE, NULL);
	self->pv->sessions_by_handle = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
	                                                      gck_util_ulong_free, g_object_unref);
	self->pv->virtual_slots_by_id = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
	                                                       gck_util_ulong_free, virtual_slot_free);
	self->pv->factories = g_array_new (FALSE, TRUE, sizeof (GckFactoryInfo));
	
	g_atomic_int_set (&(self->pv->handle_counter), 1);
	
	/* Register session object factories */
	gck_module_register_factory (self, GCK_FACTORY_PRIVATE_KEY);
	gck_module_register_factory (self, GCK_FACTORY_CERTIFICATE);
	gck_module_register_factory (self, GCK_FACTORY_PUBLIC_KEY);
}

static void
gck_module_dispose (GObject *obj)
{
	GckModule *self = GCK_MODULE (obj);

	if (self->pv->token_manager)
		g_object_unref (self->pv->token_manager);
	self->pv->token_manager = NULL;
	
	g_hash_table_remove_all (self->pv->virtual_slots_by_id);
	g_hash_table_remove_all (self->pv->sessions_by_handle);
	
	g_array_set_size (self->pv->factories, 0);
    
	G_OBJECT_CLASS (gck_module_parent_class)->dispose (obj);
}

static void
gck_module_finalize (GObject *obj)
{
	GckModule *self = GCK_MODULE (obj);
	
	g_assert (self->pv->token_manager == NULL);

	g_assert (g_hash_table_size (self->pv->virtual_slots_by_id) == 0);
	g_hash_table_destroy (self->pv->virtual_slots_by_id);
	self->pv->virtual_slots_by_id = NULL;
	
	g_assert (g_hash_table_size (self->pv->sessions_by_handle) == 0);
	g_hash_table_destroy (self->pv->sessions_by_handle);
	self->pv->sessions_by_handle = NULL;
	
	g_array_free (self->pv->factories, TRUE);
	self->pv->factories = NULL;

	gck_timer_shutdown ();

	G_OBJECT_CLASS (gck_module_parent_class)->finalize (obj);
}

static void
gck_module_set_property (GObject *obj, guint prop_id, const GValue *value, 
                         GParamSpec *pspec)
{
	GckModule *self = GCK_MODULE (obj);
	CK_C_INITIALIZE_ARGS_PTR args;
	
	switch (prop_id) {
	case PROP_INITIALIZE_ARGS:
		args = g_value_get_pointer (value);
		if (args != NULL && args->pReserved != NULL) 
			parse_arguments (self, args->pReserved);
		break;
	case PROP_MUTEX:
		self->pv->mutex = g_value_get_pointer (value);
		g_return_if_fail (self->pv->mutex);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_module_get_property (GObject *obj, guint prop_id, GValue *value, 
                         GParamSpec *pspec)
{
	GckModule *self = GCK_MODULE (obj);
	
	switch (prop_id) {
	case PROP_MANAGER:
		g_value_set_object (value, gck_module_get_manager (self));
		break;
	case PROP_WRITE_PROTECTED:
		g_value_set_boolean (value, gck_module_get_write_protected (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_module_class_init (GckModuleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gck_module_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckModulePrivate));

	gobject_class->constructor = gck_module_constructor;
	gobject_class->dispose = gck_module_dispose;
	gobject_class->finalize = gck_module_finalize;
	gobject_class->set_property = gck_module_set_property;
	gobject_class->get_property = gck_module_get_property;
    
	klass->get_slot_info = gck_module_real_get_slot_info;
	klass->get_token_info = gck_module_real_get_token_info;
	klass->parse_argument = gck_module_real_parse_argument;
	klass->refresh_token = gck_module_real_refresh_token;
	klass->store_token_object = gck_module_real_store_token_object;
	klass->remove_token_object = gck_module_real_remove_token_object;
	klass->login_change = gck_module_real_login_change;
	klass->login_user = gck_module_real_login_user;
	klass->logout_user = gck_module_real_logout_any;
	klass->login_so = gck_module_real_login_so;
	klass->logout_so = gck_module_real_logout_any;
	
	g_object_class_install_property (gobject_class, PROP_MANAGER,
	           g_param_spec_object ("manager", "Manager", "Token object manager", 
	                                GCK_TYPE_MANAGER, G_PARAM_READABLE));
	
	g_object_class_install_property (gobject_class, PROP_WRITE_PROTECTED,
	           g_param_spec_boolean ("write-protected", "Write Protected", "Token is write protected", 
	                                 TRUE, G_PARAM_READABLE));
	
	g_object_class_install_property (gobject_class, PROP_INITIALIZE_ARGS,
	           g_param_spec_pointer ("initialize-args", "Initialize Args", "Arguments passed to C_Initialize", 
	                                 G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_MUTEX,
	           g_param_spec_pointer ("mutex", "Mutex", "Module mutex",
	                                 G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckManager*
gck_module_get_manager (GckModule *self)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	g_return_val_if_fail (GCK_IS_MANAGER (self->pv->token_manager), NULL);
	return self->pv->token_manager;
}

gboolean
gck_module_get_write_protected (GckModule *self)
{
	const CK_TOKEN_INFO* info;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), TRUE);
	g_return_val_if_fail (GCK_MODULE_GET_CLASS (self)->get_token_info, TRUE);
	
	info = (GCK_MODULE_GET_CLASS (self)->get_token_info) (self);
	g_return_val_if_fail (info, TRUE);
	
	return info->flags & CKF_WRITE_PROTECTED;
}

GckSession*
gck_module_lookup_session (GckModule *self, CK_SESSION_HANDLE handle)
{
	GckSession *session;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	
	session = g_hash_table_lookup (self->pv->sessions_by_handle, &handle);
	if (!session)
		return NULL;
	
	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);
	return session;
}

CK_RV
gck_module_login_change (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR old_pin, 
                         CK_ULONG n_old_pin, CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->login_change);
	return GCK_MODULE_GET_CLASS (self)->login_change (self, slot_id, old_pin, n_old_pin, new_pin, n_new_pin);
}

CK_RV
gck_module_login_user (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->login_user);
	return GCK_MODULE_GET_CLASS (self)->login_user (self, slot_id, pin, n_pin);
}

CK_RV
gck_module_logout_user (GckModule *self, CK_SLOT_ID slot_id)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->logout_user);
	return GCK_MODULE_GET_CLASS (self)->logout_user (self, slot_id);	
}

CK_RV
gck_module_login_so (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->login_so);
	return GCK_MODULE_GET_CLASS (self)->login_so (self, slot_id, pin, n_pin);
}

CK_RV
gck_module_logout_so (GckModule *self, CK_SLOT_ID slot_id)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->logout_so);
	return GCK_MODULE_GET_CLASS (self)->logout_so (self, slot_id);	
}

CK_ULONG
gck_module_next_handle (GckModule *self)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), 0);
	if (self->pv->handle_counter == CK_GNOME_MAX_HANDLE) {
		g_warning ("handle counter wrapped");
		self->pv->handle_counter = 0;
	}
	return (self->pv->handle_counter)++;
}

CK_RV
gck_module_refresh_token (GckModule *self)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_GENERAL_ERROR);
	g_assert (GCK_MODULE_GET_CLASS (self)->refresh_token);
	return GCK_MODULE_GET_CLASS (self)->refresh_token (self);	
}

void
gck_module_store_token_object (GckModule *self, GckTransaction *transaction, GckObject *object)
{
	g_return_if_fail (GCK_IS_MODULE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_assert (GCK_MODULE_GET_CLASS (self)->store_token_object);
	GCK_MODULE_GET_CLASS (self)->store_token_object (self, transaction, object);
}

void
gck_module_remove_token_object (GckModule *self, GckTransaction *transaction, GckObject *object)
{
	g_return_if_fail (GCK_IS_MODULE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_assert (GCK_MODULE_GET_CLASS (self)->remove_token_object);
	GCK_MODULE_GET_CLASS (self)->remove_token_object (self, transaction, object);
}

void
gck_module_register_factory (GckModule *self, GckFactoryInfo *factory)
{
	g_return_if_fail (GCK_IS_MODULE (self));
	g_return_if_fail (factory);
	g_return_if_fail (factory->attrs || !factory->n_attrs);
	g_return_if_fail (factory->factory);
	
	g_array_append_val (self->pv->factories, *factory);
	self->pv->factories_sorted = FALSE;
}

GckFactory
gck_module_find_factory (GckModule *self, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GckFactoryInfo *factory;
	gboolean matched;
	gulong j;
	gsize i;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);
	
	if (!self->pv->factories_sorted) {
		g_array_sort (self->pv->factories, sort_factory_by_n_attrs);
		self->pv->factories_sorted = TRUE;
	}
	
	for (i = 0; i < self->pv->factories->len; ++i) {
		factory = &(g_array_index (self->pv->factories, GckFactoryInfo, i));
		
		matched = TRUE;
		for (j = 0; j < factory->n_attrs; ++j) {
			if (!gck_attributes_contains (attrs, n_attrs, &factory->attrs[j])) {
				matched = FALSE;
				break;
			}
		}
		
		if (matched)
			return factory->factory;
	}
	
	return NULL;
}

/*
 * Hidden method to get the mutex for a module. This is for timers to be
 * able to reenter the module. Don't use this method.
 */

GMutex*
_gck_module_get_scary_mutex_that_you_should_not_touch (GckModule *self)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), NULL);
	return self->pv->mutex;
}

/* -----------------------------------------------------------------------------
 * PKCS#11
 */

CK_RV
gck_module_C_GetInfo (GckModule *self, CK_INFO_PTR info)
{
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (!info)
		return CKR_ARGUMENTS_BAD;
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	
	memcpy (info, &default_module_info, sizeof (CK_INFO));
	
	/* Extend all the strings appropriately */
	extend_space_string (info->libraryDescription, sizeof (info->libraryDescription));
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	
	return CKR_OK;
}

CK_RV
gck_module_C_GetSlotList (GckModule *self, CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (!count)
		return CKR_ARGUMENTS_BAD;
	
	/* Just want to get the count */
	if (slot_list == NULL) {
		*count = 1;
		return CKR_OK;
	}
	
	/* Buffer too small? */
	if (*count == 0) {
		*count = 1;
		return CKR_BUFFER_TOO_SMALL;
	}
	
	g_return_val_if_fail (slot_list, CKR_ARGUMENTS_BAD);
	
	/* Answer C_GetSlotList with 0 for app */
	slot_list[0] = CK_GNOME_MAKE_APPARTMENT (GCK_SLOT_ID, 0);
	*count = 1;
	return CKR_OK;
}

CK_RV
gck_module_C_GetSlotInfo (GckModule *self, CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	const CK_SLOT_INFO *original;
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	
	/* Any slot ID is valid for partitioned module */
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	g_return_val_if_fail (klass->get_slot_info, CKR_GENERAL_ERROR);
	
	original = (klass->get_slot_info) (self);
	g_return_val_if_fail (original, CKR_GENERAL_ERROR);
	
	memcpy (info, original, sizeof (CK_SLOT_INFO));
	
	/* Extend all the strings appropriately */
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	extend_space_string (info->slotDescription, sizeof (info->slotDescription));
	
	return CKR_OK;
}

CK_RV
gck_module_C_GetTokenInfo (GckModule *self, CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	const CK_TOKEN_INFO *original;
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	
	/* Any slot ID is valid for partitioned module */
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	g_return_val_if_fail (klass->get_token_info, CKR_GENERAL_ERROR);
	
	original = (klass->get_token_info) (self);
	g_return_val_if_fail (original, CKR_GENERAL_ERROR);
	
	memcpy (info, original, sizeof (CK_TOKEN_INFO));

	/* Extend all the strings appropriately */
	extend_space_string (info->label, sizeof (info->label));
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	extend_space_string (info->model, sizeof (info->model));
	extend_space_string (info->serialNumber, sizeof (info->serialNumber));

	return CKR_OK;
}

CK_RV
gck_module_C_GetMechanismList (GckModule *self, CK_SLOT_ID id, 
                               CK_MECHANISM_TYPE_PTR mech_list, CK_ULONG_PTR count)
{
	const guint n_mechanisms = G_N_ELEMENTS (mechanism_list); 
	guint i;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if (count == NULL)
		return CKR_ARGUMENTS_BAD;
	
	/* Just want to get the count */
	if (mech_list == NULL) {
		*count = n_mechanisms;
		return CKR_OK;
	}
	
	/* Buffer too small? */
	if (*count < n_mechanisms) {
		*count = n_mechanisms;
		return CKR_BUFFER_TOO_SMALL;
	}
	
	*count = n_mechanisms;
	for (i = 0; i < n_mechanisms; ++i)
		mech_list[i] = mechanism_list[i].mechanism;

	return CKR_OK;
}

CK_RV
gck_module_C_GetMechanismInfo (GckModule *self, CK_SLOT_ID id, 
                               CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
	const guint n_mechanisms = G_N_ELEMENTS (mechanism_list); 
	guint index;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	for (index = 0; index < n_mechanisms; ++index) {
		if (mechanism_list[index].mechanism == type)
			break;
	}
	
	if (index == n_mechanisms)
		return CKR_MECHANISM_INVALID;

	memcpy (info, &mechanism_list[index].info, sizeof (CK_MECHANISM_INFO));
	return CKR_OK;
}

CK_RV
gck_module_C_InitToken (GckModule *self, CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, 
                        CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_module_C_OpenSession (GckModule *self, CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data, 
                          CK_NOTIFY callback, CK_SESSION_HANDLE_PTR result)
{
	CK_SESSION_HANDLE handle;
	VirtualSlot *slot;
	gboolean read_only;
	GckSession *session;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;
	if (!result)
		return CKR_ARGUMENTS_BAD;
	
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	/* Lookup or register the virtual slot */
	slot = lookup_virtual_slot (self, id);
	if (slot == NULL) {
		slot = virtual_slot_new (GCK_MODULE_GET_CLASS (self), id);
		register_virtual_slot (self, slot);
	}
	
	/* Can't open read only session if SO login */
	if (slot->logged_in == CKU_SO && !(flags & CKF_RW_SESSION))
		return CKR_SESSION_READ_WRITE_SO_EXISTS; 

	/* Make and register a new session */
	handle = gck_module_next_handle (self);
	read_only = !(flags & CKF_RW_SESSION);
	session = g_object_new (GCK_TYPE_SESSION, "slot-id", slot->slot_id, 
	                        "read-only", read_only, "handle", handle, "module", self, 
	                        "manager", slot->session_manager, "logged-in", slot->logged_in, NULL);
	slot->sessions = g_list_prepend (slot->sessions, session);
	
	/* Track the session by handle */
	g_hash_table_insert (self->pv->sessions_by_handle, 
	                     gck_util_ulong_alloc (handle), 
	                     g_object_ref (session));
	
	*result = handle;
	return CKR_OK;
}

CK_RV
gck_module_C_CloseSession (GckModule *self, CK_SESSION_HANDLE handle)
{
	GckSession *session;
	CK_SLOT_ID slot_id;
	VirtualSlot *slot;
	GList *link;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	/* Calculate the virtual slot */
	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	link = g_list_find (slot->sessions, session);
	g_return_val_if_fail (link, CKR_GENERAL_ERROR);
	slot->sessions = g_list_delete_link (slot->sessions, link);
	g_object_unref (session);
	if (!slot->sessions) 
		unregister_virtual_slot (self, slot);

	if (!g_hash_table_remove (self->pv->sessions_by_handle, &handle))
		g_assert_not_reached ();
	
	return CKR_OK;
}

CK_RV
gck_module_C_CloseAllSessions (GckModule *self, CK_SLOT_ID id)
{
	VirtualSlot *slot;
	CK_SESSION_HANDLE handle;
	GList *l;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	if (CK_GNOME_APPARTMENT_SLOT (id) != GCK_SLOT_ID)
		return CKR_SLOT_ID_INVALID;

	/* Calculate the virtual slot */
	slot = lookup_virtual_slot (self, id);
	if (slot == NULL)
		return CKR_OK;
	
	/* Unregister all its sessions */
	for (l = slot->sessions; l; l = g_list_next (l)) {
		handle = gck_session_get_handle (l->data);
		if (!g_hash_table_remove (self->pv->sessions_by_handle, &handle))
			g_assert_not_reached ();
	}

	unregister_virtual_slot (self, slot);
	return CKR_OK;	
}

CK_RV
gck_module_C_InitPIN (GckModule* self, CK_SESSION_HANDLE handle, 
                      CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	GckSession *session;
	VirtualSlot *slot;
	CK_SLOT_ID slot_id;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;
	
	/* Calculate the virtual slot */
	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);
	
	if (slot->logged_in != CKU_SO)
		return CKR_USER_NOT_LOGGED_IN;

	/* Our InitPIN assumes an uninitialized PIN */
	return gck_module_login_change (self, slot_id, NULL, 0, pin, n_pin);
}

CK_RV
gck_module_C_SetPIN (GckModule* self, CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR old_pin,
                     CK_ULONG old_pin_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len)
{
	GckSession *session;
	VirtualSlot *slot;
	CK_SLOT_ID slot_id;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	/* Calculate the virtual slot */
	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	return gck_module_login_change (self, slot_id, old_pin, old_pin_len, new_pin, new_pin_len);
}

CK_RV
gck_module_C_Login (GckModule *self, CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
                    CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_SLOT_ID slot_id;
	GckSession *session;
	VirtualSlot *slot;
	GList *l;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	/* Pass off context specifc logins to appropriate place */
	if (user_type == CKU_CONTEXT_SPECIFIC)
		return gck_session_login_context_specific (session, pin, pin_len);

	/* Some random crap... */
	if (user_type != CKU_USER && user_type != CKU_SO)
		return CKR_USER_TYPE_INVALID;

	/* Calculate the virtual slot */
	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	if (slot->logged_in != CKU_NONE)
		return CKR_USER_ALREADY_LOGGED_IN;

	if (user_type == CKU_SO) {
		
		/* Can't login as SO if read-only sessions exist */
		for (l = slot->sessions; l; l = g_list_next (l)) {
			if (gck_session_get_read_only (l->data))
				return CKR_SESSION_READ_ONLY_EXISTS;
		}
		
		return gck_module_login_so (self, slot_id, pin, pin_len);
				
	} else if (user_type == CKU_USER) {
		return gck_module_login_user (self, slot_id, pin, pin_len);
		
	} else {
		return CKR_USER_TYPE_INVALID;
	}
}

CK_RV
gck_module_C_Logout (GckModule *self, CK_SESSION_HANDLE handle)
{
	CK_SLOT_ID slot_id;
	VirtualSlot *slot;
	GckSession *session;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	if (slot->logged_in == CKU_NONE)
		return CKR_USER_NOT_LOGGED_IN;
	
	else if (slot->logged_in == CKU_USER)
		return gck_module_logout_user (self, slot_id);

	else if (slot->logged_in == CKU_SO)
		return gck_module_logout_so (self, slot_id);

	else 
		g_return_val_if_reached (CKR_GENERAL_ERROR);
}
