
#include "config.h"

#include "gp11.h"
#include "gp11-private.h"

#include <string.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_HANDLE
};

G_DEFINE_TYPE (GP11Slot, gp11_slot, G_TYPE_OBJECT);

/* ----------------------------------------------------------------------------
 * OBJECT
 */

static void
gp11_slot_init (GP11Slot *slot)
{
	
}

static void
gp11_slot_get_property (GObject *obj, guint prop_id, GValue *value, 
                        GParamSpec *pspec)
{
	GP11Slot *slot = GP11_SLOT (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_set_object (value, slot->module);
		break;
	case PROP_HANDLE:
		g_value_set_uint (value, slot->handle);
		break;
	}
}

static void
gp11_slot_set_property (GObject *obj, guint prop_id, const GValue *value, 
                        GParamSpec *pspec)
{
	GP11Slot *slot = GP11_SLOT (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_return_if_fail (!slot->module);
		slot->module = g_value_get_object (value);
		g_return_if_fail (slot->module);
		g_object_ref (slot->module);
		break;
	case PROP_HANDLE:
		g_return_if_fail (!slot->handle);
		slot->handle = g_value_get_uint (value);
		break;
	}
}

static void
gp11_slot_dispose (GObject *obj)
{
	GP11Slot *slot = GP11_SLOT (obj);
	
	if (slot->module)
		g_object_unref (slot->module);
	slot->module = NULL;

	G_OBJECT_CLASS (gp11_slot_parent_class)->dispose (obj);
}

static void
gp11_slot_finalize (GObject *obj)
{
	GP11Slot *slot = GP11_SLOT (obj);

	g_assert (slot->module == NULL);
	slot->handle = 0;
	
	G_OBJECT_CLASS (gp11_slot_parent_class)->finalize (obj);
}


static void
gp11_slot_class_init (GP11SlotClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	gp11_slot_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gp11_slot_get_property;
	gobject_class->set_property = gp11_slot_set_property;
	gobject_class->dispose = gp11_slot_dispose;
	gobject_class->finalize = gp11_slot_finalize;
	
	g_object_class_install_property (gobject_class, PROP_MODULE,
		g_param_spec_object ("module", "Module", "PKCS11 Module",
		                     GP11_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
		g_param_spec_uint ("handle", "Handle", "PKCS11 Slot ID",
		                   0, G_MAXUINT, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* ----------------------------------------------------------------------------
 * PUBLIC 
 */

void
gp11_slot_info_free (GP11SlotInfo *slot_info)
{
	if (!slot_info)
		return;
	g_free (slot_info->slot_description);
	g_free (slot_info->manufacturer_id);
	g_free (slot_info);
}

void
gp11_token_info_free (GP11TokenInfo *token_info)
{
	if (!token_info)
		return;
	g_free (token_info->label);
	g_free (token_info->manufacturer_id);
	g_free (token_info->model);
	g_free (token_info->serial_number);
	g_free (token_info);
}

void
gp11_mechanism_info_free (GP11MechanismInfo *mech_info)
{
	if (!mech_info)
		return;
	g_free (mech_info);
}

GP11SlotInfo*
gp11_slot_get_info (GP11Slot *slot)
{
	GP11SlotInfo *slotinfo;
	CK_SLOT_INFO info;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (slot->module), NULL);
	g_return_val_if_fail (slot->module->funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (slot->module->funcs->C_GetSlotInfo) (slot->handle, &info);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	slotinfo = g_new0 (GP11SlotInfo, 1);
	slotinfo->slot_description = gp11_string_from_chars (info.slotDescription, 
	                                                     sizeof (info.slotDescription));
	slotinfo->manufacturer_id = gp11_string_from_chars (info.manufacturerID, 
	                                                    sizeof (info.manufacturerID));
	slotinfo->flags = info.flags;
	slotinfo->hardware_version_major = info.hardwareVersion.major;
	slotinfo->hardware_version_minor = info.hardwareVersion.minor;
	slotinfo->firmware_version_major = info.firmwareVersion.major;
	slotinfo->firmware_version_minor = info.firmwareVersion.minor;

	return slotinfo;
}

GP11TokenInfo*
gp11_slot_get_token_info (GP11Slot *slot)
{
	GP11TokenInfo *tokeninfo;
	CK_TOKEN_INFO info;
	gchar *string;
	struct tm tm;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (slot->module), NULL);
	g_return_val_if_fail (slot->module->funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (slot->module->funcs->C_GetTokenInfo) (slot->handle, &info);
	if (rv != CKR_OK) {
		g_warning ("couldn't get slot info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	tokeninfo = g_new0 (GP11TokenInfo, 1);
	tokeninfo->label = gp11_string_from_chars (info.label, sizeof (info.label));
	tokeninfo->model = gp11_string_from_chars (info.model, sizeof (info.model));
	tokeninfo->manufacturer_id = gp11_string_from_chars (info.manufacturerID, 
	                                                     sizeof (info.manufacturerID));
	tokeninfo->serial_number = gp11_string_from_chars (info.serialNumber, 
	                                                   sizeof (info.serialNumber));
	tokeninfo->flags = info.flags;
	tokeninfo->max_session_count = info.ulMaxSessionCount;
	tokeninfo->session_count = info.ulSessionCount;
	tokeninfo->max_rw_session_count = info.ulMaxRwSessionCount;
	tokeninfo->rw_session_count = info.ulRwSessionCount;
	tokeninfo->max_pin_len = info.ulMaxPinLen;
	tokeninfo->min_pin_len = info.ulMinPinLen;
	tokeninfo->total_public_memory = info.ulTotalPublicMemory;
	tokeninfo->total_private_memory = info.ulTotalPrivateMemory;
	tokeninfo->free_private_memory = info.ulFreePrivateMemory;
	tokeninfo->free_public_memory = info.ulFreePublicMemory;
	tokeninfo->hardware_version_major = info.hardwareVersion.major;
	tokeninfo->hardware_version_minor = info.hardwareVersion.minor;
	tokeninfo->firmware_version_major = info.firmwareVersion.major;
	tokeninfo->firmware_version_minor = info.firmwareVersion.minor;
	
	/* Parse the time into seconds since epoch */
	if (info.flags & CKF_CLOCK_ON_TOKEN) {
		string = g_strndup ((gchar*)info.utcTime, MIN (14, sizeof (info.utcTime)));
		if (!strptime (string, "%Y%m%d%H%M%S", &tm))
			tokeninfo->utc_time = -1;
		else
			tokeninfo->utc_time = mktime (&tm);
	} else {
		tokeninfo->utc_time = -1;
	}
	
	return tokeninfo;
}

GSList*
gp11_slot_get_mechanisms (GP11Slot *slot)
{
	CK_MECHANISM_TYPE_PTR mech_list;
	CK_ULONG count, i;
	GSList *result;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (slot->module), NULL);
	g_return_val_if_fail (slot->module->funcs, NULL);

	rv = (slot->module->funcs->C_GetMechanismList) (slot->handle, NULL, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get mechanism count: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	if (!count)
		return NULL;
	
	mech_list = g_new (CK_MECHANISM_TYPE, count);
	rv = (slot->module->funcs->C_GetMechanismList) (slot->handle, mech_list, &count);
	if (rv != CKR_OK) {
		g_warning ("couldn't get mechanism list: %s", gp11_message_from_rv (rv));
		g_free (mech_list);
		return NULL;
	}
	
	result = NULL;
	for (i = 0; i < count; ++i)
		result = g_slist_prepend (result, GUINT_TO_POINTER (mech_list[i]));
	
	g_free (mech_list);
	return g_slist_reverse (result);

}

GP11MechanismInfo*
gp11_slot_get_mechanism_info (GP11Slot *slot, guint mech_type)
{
	GP11MechanismInfo *mechinfo;
	CK_MECHANISM_INFO info;
	struct tm;
	CK_RV rv;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), NULL);
	g_return_val_if_fail (GP11_IS_MODULE (slot->module), NULL);
	g_return_val_if_fail (slot->module->funcs, NULL);
	
	memset (&info, 0, sizeof (info));
	rv = (slot->module->funcs->C_GetMechanismInfo) (slot->handle, mech_type, &info);
	if (rv != CKR_OK) {
		g_warning ("couldn't get mechanism info: %s", gp11_message_from_rv (rv));
		return NULL;
	}
	
	mechinfo = g_new0 (GP11MechanismInfo, 1);
	mechinfo->flags = info.flags;
	mechinfo->max_key_size = info.ulMaxKeySize;
	mechinfo->min_key_size = info.ulMinKeySize;
	
	return mechinfo;
}

#if UNIMPLEMENTED

typedef struct InitToken {
	GP11Arguments base;
	const guchar *pin;
	gsize length;
	const gchar *label;
} InitToken;

static CK_RV
perform_init_token (InitToken *args)
{
	return (args->base.pkcs11->C_InitToken) (args->base.handle, 
	                                         args->pin, args->length, 
	                                         args->label);
}

gboolean
gp11_slot_init_token (GP11Slot *slot, const guchar *pin, gsize length, 
                      const gchar *label, GCancellable *cancellable,
                      GError **err)
{
	InitToken args = { GP11_ARGUMENTS_INIT, pin, length, label };
	return _gp11_call_sync (slot, perform_init_token, &args, err);
}

void
gp11_slot_init_token_async (GP11Slot *slot, const guchar *pin, gsize length, 
                            const gchar *label, GCancellable *cancellable,
                            GAsyncReadyCallback callback, gpointer user_data)
{
	InitToken* args = _gp11_call_async_prep (slot, perform_init_token, 
	                                         sizeof (*args));
	
	args->pin = pin;
	args->length = length;
	args->label = label;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}
	
gboolean
gp11_slot_init_token_finish (GP11Slot *slot, GAsyncResult *result, GError **err)
{
	return _gp11_call_basic_finish (slot, result, err);
}

#endif /* UNIMPLEMENTED */

typedef struct OpenSession {
	GP11Arguments base;
	guint flags;
	CK_SESSION_HANDLE session;
} OpenSession;

static CK_RV
perform_open_session (OpenSession *args)
{
	return (args->base.pkcs11->C_OpenSession) (args->base.handle, 
	                                           args->flags | CKF_SERIAL_SESSION, 
	                                           NULL, NULL, &args->session);
}

GP11Session*
gp11_slot_open_session (GP11Slot *slot, guint flags, GError **err)
{
	return gp11_slot_open_session_full (slot, flags, NULL, err);
}

GP11Session*
gp11_slot_open_session_full (GP11Slot *slot, guint flags, GCancellable *cancellable, GError **err)
{
	OpenSession args = { GP11_ARGUMENTS_INIT, flags, 0 };
	
	if (!_gp11_call_sync (slot, perform_open_session, &args, cancellable, err))
		return FALSE;
	
	return gp11_session_from_handle (slot, args.session);
}

void
gp11_slot_open_session_async (GP11Slot *slot, guint flags, GCancellable *cancellable, 
                              GAsyncReadyCallback callback, gpointer user_data)
{
	OpenSession *args = _gp11_call_async_prep (slot, perform_open_session,
	                                           sizeof (*args), NULL);
	
	args->flags = flags;
	args->session = 0;
	
	_gp11_call_async_go (args, cancellable, callback, user_data);
}

GP11Session*
gp11_slot_open_session_finish (GP11Slot *slot, GAsyncResult *result, GError **err)
{
	OpenSession *args;
	
	if (!_gp11_call_basic_finish (slot, result, err))
		return NULL;
	
	args = _gp11_call_arguments (result, OpenSession);
	return gp11_session_from_handle (slot, args->session);
}

#if UNIMPLEMENTED

static CK_RV
perform_close_all_sessions (GP11Arguments *args)
{
	return (args->pkcs11->C_CloseAllSessions) (args->handle);
}

gboolean
gp11_slot_close_all_sessions (GP11Slot *slot, GError **err)
{
	return gp11_slot_close_all_sessions_full (slot, NULL, err);
}

gboolean
gp11_slot_close_all_sessions_full (GP11Slot *slot, GCancellable *cancellable, GError **err)
{
	GP11Arguments args = GP11_ARGUMENTS_INIT;
	return _gp11_call_sync (slot, perform_close_all_sessions, &args, cancellable, err);
}

void
gp11_slot_close_all_sessions_async (GP11Slot *slot, GCancellable *cancellable, 
                                    GAsyncReadyCallback callback, gpointer user_data)
{
	GP11Arguments *args = _gp11_call_async_prep (slot, perform_close_all_sessions, 0, NULL);
	_gp11_call_async_go (args, cancellable, callback, user_data);	
}

gboolean
gp11_slot_close_all_sessions_finish (GP11Slot *slot, GAsyncResult *result,
                                     GError **err)
{
	return _gp11_call_basic_finish (slot, result, err);
}

#endif
