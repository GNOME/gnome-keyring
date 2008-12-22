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

#include "gck-manager.h"
#include "gck-module.h"
#include "gck-session.h"
#include "gck-util.h"


enum {
	PROP_0,
	PROP_MANAGER,
	PROP_WRITE_PROTECTED
};

#if 0
enum {
	SIGNAL,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };
#endif

struct _GckModulePrivate {
	GckManager *token_manager; 
	GHashTable *virtual_slots_by_id;        /* Various slot partitions by their ID */
	GHashTable *sessions_by_handle;         /* Mapping of handle to all open sessions */
	gint handle_counter;                    /* Constantly incrementing counter for handles and the like */
};

typedef struct _VirtualSlot {
	CK_SLOT_ID slot_id;
	GckManager *session_manager;
	GList *sessions;
	gboolean logged_in;
} VirtualSlot;

G_DEFINE_TYPE (GckModule, gck_module, G_TYPE_OBJECT);

/* These info blocks are used unless derived class overrides */

static const CK_INFO default_module_info = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	"Gnome Keyring",
	0,
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

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
extend_space_string (CK_UTF8CHAR_PTR string, gsize length)
{
	CK_UTF8CHAR_PTR at;
	
	/* Find a null pointer in the string */
	at = memchr (string, '0', length);
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
virtual_slot_new (CK_SLOT_ID slot_id)
{
	VirtualSlot *slot;

	slot = g_slice_new0 (VirtualSlot);
	slot->session_manager = g_object_new (GCK_TYPE_MANAGER, "is-token", FALSE, NULL);
	slot->logged_in = FALSE;
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
	
	return g_hash_table_insert (self->pv->virtual_slots_by_id, 
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

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_module_real_refresh_token (GckModule *self)
{
	/* Derived classes should do something interesting */
	return CKR_OK;
}

static CK_RV
gck_module_real_login_user (GckModule *self, CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	VirtualSlot *slot;
	GList *l;
	
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	/* Mark all sessions in the partition as logged in */
	for (l = slot->sessions; l; l = g_list_next (l)) 
		gck_session_set_logged_in (l->data, TRUE);
	slot->logged_in = TRUE;
	
	return CKR_OK;
}

static CK_RV
gck_module_real_logout_user (GckModule *self, CK_SLOT_ID slot_id)
{
	VirtualSlot *slot;
	GList *l;

	/* Calculate the partition identifier */
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	/* Mark all sessions in the partition as logged out */
	for (l = slot->sessions; l; l = g_list_next (l)) 
		gck_session_set_logged_in (l->data, FALSE);
	slot->logged_in = FALSE;
	
	/* Derived classes should override if they want actual login */
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
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_MODULE, GckModulePrivate);
	self->pv->token_manager = g_object_new (GCK_TYPE_MANAGER, "is-token", TRUE, NULL);
	self->pv->sessions_by_handle = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
	                                                      gck_util_ulong_free, g_object_unref);
	self->pv->virtual_slots_by_id = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
	                                                       gck_util_ulong_free, virtual_slot_free);
	
	g_atomic_int_set (&(self->pv->handle_counter), 1);
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

	G_OBJECT_CLASS (gck_module_parent_class)->finalize (obj);
}

static void
gck_module_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
#if 0
	GckModule *self = GCK_MODULE (obj);
#endif 
	
	switch (prop_id) {
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
    
	klass->module_info = &default_module_info;
	klass->slot_info = &default_slot_info;
	klass->token_info = &default_token_info;
	
	klass->refresh_token = gck_module_real_refresh_token;
	klass->login_user = gck_module_real_login_user;
	klass->logout_user = gck_module_real_logout_user;
	
	g_object_class_install_property (gobject_class, PROP_MANAGER,
	           g_param_spec_object ("manager", "Manager", "Token object manager", 
	                                GCK_TYPE_MANAGER, G_PARAM_READABLE));
	
	g_object_class_install_property (gobject_class, PROP_WRITE_PROTECTED,
	           g_param_spec_boolean ("write-protected", "Write Protected", "Token is write protected", 
	                                 TRUE, G_PARAM_READABLE));

#if 0
	signals[SIGNAL] = g_signal_new ("signal", GCK_TYPE_MODULE, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckModuleClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
	                                G_TYPE_NONE, 0);
#endif
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckModule*
gck_module_new (void)
{
	return g_object_new (GCK_TYPE_MODULE, NULL);
}

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
	g_return_val_if_fail (GCK_IS_MODULE (self), FALSE);
	g_return_val_if_fail (GCK_MODULE_GET_CLASS (self)->token_info, FALSE);
	return (GCK_MODULE_GET_CLASS (self)->token_info->flags & CKF_WRITE_PROTECTED) ? TRUE : FALSE;
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

CK_ULONG
gck_module_next_handle (GckModule *self)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), 0);
	return (self->pv->handle_counter)++;
}

/* -----------------------------------------------------------------------------
 * PKCS#11
 */

CK_RV
gck_module_C_GetInfo (GckModule *self, CK_INFO_PTR info)
{
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (info, CKR_ARGUMENTS_BAD);
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	
	memcpy (info, klass->module_info, sizeof (CK_INFO));
	
	/* Extend all the strings appropriately */
	extend_space_string (info->libraryDescription, sizeof (info->libraryDescription));
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	
	return CKR_OK;
}

CK_RV
gck_module_C_GetSlotList (GckModule *self, CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (count, CKR_ARGUMENTS_BAD);
	
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
	
	slot_list[0] = 0;
	*count = 1;
	return CKR_OK;
}

CK_RV
gck_module_C_GetSlotInfo (GckModule *self, CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (info, CKR_ARGUMENTS_BAD);
	
	/* Any slot ID is valid for partitioned module */
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	
	memcpy (info, klass->slot_info, sizeof (CK_SLOT_INFO));
	
	/* Extend all the strings appropriately */
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	extend_space_string (info->slotDescription, sizeof (info->slotDescription));
	
	return CKR_OK;
}

CK_RV
gck_module_C_GetTokenInfo (GckModule *self, CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	GckModuleClass *klass;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (info, CKR_ARGUMENTS_BAD);
	
	/* Any slot ID is valid for partitioned module */
	
	klass = GCK_MODULE_GET_CLASS (self);
	g_return_val_if_fail (klass, CKR_GENERAL_ERROR);
	
	memcpy (info, klass->token_info, sizeof (CK_TOKEN_INFO));
	
	/* Extend all the strings appropriately */
	extend_space_string (info->label, sizeof (info->label));
	extend_space_string (info->manufacturerID, sizeof (info->manufacturerID));
	extend_space_string (info->model, sizeof (info->model));
	extend_space_string (info->serialNumber, sizeof (info->serialNumber));
	
	/* We don't purport to have a clock */
	memset (info->utcTime, 0, sizeof (info->utcTime));
	
	return CKR_OK;	
}

CK_RV
gck_module_C_GetMechanismList (GckModule *self, CK_SLOT_ID id, 
                               CK_MECHANISM_TYPE_PTR mech_list, CK_ULONG_PTR count)
{
	const guint n_mechanisms = G_N_ELEMENTS (mechanism_list); 
	guint i;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (count, CKR_ARGUMENTS_BAD);
	
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
	
	g_return_val_if_fail (mech_list, CKR_ARGUMENTS_BAD);
	
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
	g_return_val_if_fail (info, CKR_ARGUMENTS_BAD);

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
gck_module_C_OpenSession (GckModule *self, CK_SLOT_ID slot_id, CK_FLAGS flags, CK_VOID_PTR user_data, 
                          CK_NOTIFY callback, CK_SESSION_HANDLE_PTR result)
{
	CK_SESSION_HANDLE handle;
	VirtualSlot *slot;
	gboolean read_only;
	GckSession *session;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	g_return_val_if_fail (handle, CKR_ARGUMENTS_BAD);
	
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	/* Lookup or register the virtual slot */
	slot = lookup_virtual_slot (self, slot_id);
	if (slot == NULL) {
		slot = virtual_slot_new (slot_id);
		register_virtual_slot (self, slot);
	}

	/* Make and register a new session */
	handle = gck_module_next_handle (self);
	read_only = !(flags & CKF_RW_SESSION);
	session = g_object_new (GCK_TYPE_SESSION, "slot-id", slot->slot_id, "read-only", read_only, 
	                        "handle", handle, "module", self, "manager", slot->session_manager, 
	                        "logged-in", slot->logged_in, NULL);
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
gck_module_C_CloseAllSessions (GckModule *self, CK_SLOT_ID slot_id)
{
	VirtualSlot *slot;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	/* Calculate the virtual slot */
	slot = lookup_virtual_slot (self, slot_id);
	if (!slot)
		return CKR_OK;

	unregister_virtual_slot (self, slot);
	return CKR_OK;	
}

CK_RV
gck_module_C_Login (GckModule *self, CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
                    CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_SLOT_ID slot_id;
	GckSession *session;
	VirtualSlot *slot;
	
	g_return_val_if_fail (GCK_IS_MODULE (self), CKR_CRYPTOKI_NOT_INITIALIZED);
	
	session = gck_module_lookup_session (self, handle);
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	/* Pass off context specifc logins to appropriate place */
	if (user_type == CKU_CONTEXT_SPECIFIC)
		return gck_session_login_context_specific (session, pin, pin_len);

	/* We don't have support for SO logins */
	if (user_type == CKU_SO) 
		return CKR_USER_TYPE_INVALID;

	/* Calculate the virtual slot */
	slot_id = gck_session_get_slot_id (session);
	slot = lookup_virtual_slot (self, slot_id);
	g_return_val_if_fail (slot, CKR_GENERAL_ERROR);

	if (slot->logged_in)
		return CKR_USER_ALREADY_LOGGED_IN;
	
	return gck_module_login_user (self, slot_id, pin, pin_len);
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

	if (!slot->logged_in)
		return CKR_USER_ALREADY_LOGGED_IN;

	return gck_module_logout_user (self, slot_id);
}
