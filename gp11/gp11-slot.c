
#include "config.h"

#include "gp11.h"
#include "gp11-private.h"
#include "gp11-marshal.h"

#include <string.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_HANDLE,
	PROP_REUSE_SESSIONS,
	PROP_AUTO_LOGIN
};

enum {
	AUTHENTICATE_TOKEN,
#ifdef UNIMPLEMENTED
	AUTHENTICATE_KEY,
	SLOT_EVENT
#endif
	LAST_SIGNAL
};

typedef struct _GP11SlotPrivate {
	gboolean auto_login;
	GHashTable *open_sessions;
	GP11TokenInfo *token_info;
} GP11SlotPrivate;

G_DEFINE_TYPE (GP11Slot, gp11_slot, G_TYPE_OBJECT);

#define GP11_SLOT_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GP11_TYPE_SLOT, GP11SlotPrivate))

typedef struct _SessionPool {
	guint flags;
	GP11Module *module; /* weak */
	GSList *sessions; /* list of CK_SESSION_HANDLE */
} SessionPool;

static guint signals[LAST_SIGNAL] = { 0 }; 

/* ----------------------------------------------------------------------------
 * HELPERS
 */

static void
close_session (GP11Module *module, CK_SESSION_HANDLE handle)
{
	CK_RV rv; 
	
	g_return_if_fail (GP11_IS_MODULE (module));
	g_return_if_fail (module->funcs);
	rv = (module->funcs->C_CloseSession) (handle);
	if (rv != CKR_OK) {
		g_warning ("couldn't close session properly: %s",
		           gp11_message_from_rv (rv));
	}
}

static void
free_session_pool (gpointer p)
{
	SessionPool *pool = p;
	GSList *l;
	for (l = pool->sessions; l; l = g_slist_next (l))
		close_session (pool->module, GPOINTER_TO_UINT (l->data));
	g_free (pool);
}

#ifdef UNUSED

static void
foreach_count_sessions (gpointer key, gpointer value, gpointer user_data)
{
	SessionPool *pool = value;
	guint *result = user_data;
	*result += g_slist_length (pool->sessions);
}

static guint
count_session_table (GP11Slot *slot, guint flags)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	guint result = 0;
	
	if (!pv->open_sessions)
		return 0;
	
	g_hash_table_foreach (pv->open_sessions, foreach_count_sessions, &result);
	return result;
}

#endif /* UNUSED */

static void
push_session_table (GP11Slot *slot, guint flags, CK_SESSION_HANDLE handle)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	SessionPool *pool;
	
	if (!pv->open_sessions) {
		close_session (slot->module, handle);
		return;
	}
	
	g_assert (handle);
	g_assert (GP11_IS_MODULE (slot->module));
	
	pool = g_hash_table_lookup (pv->open_sessions, GUINT_TO_POINTER (flags));
	if (!pool) {
		pool = g_new0 (SessionPool, 1);
		pool->flags = flags;
		pool->module = slot->module; /* weak ref */
		g_hash_table_insert (pv->open_sessions, GUINT_TO_POINTER (flags), pool);
	}
	
	g_assert (pool->flags == flags);
	pool->sessions = g_slist_prepend (pool->sessions, GUINT_TO_POINTER (handle));
}

static CK_SESSION_HANDLE
pop_session_table (GP11Slot *slot, guint flags)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	CK_SESSION_HANDLE result;
	SessionPool *pool;
	
	if (!pv->open_sessions)
		return 0;
	
	g_assert (GP11_IS_MODULE (slot->module));
	
	pool = g_hash_table_lookup (pv->open_sessions, GUINT_TO_POINTER (flags));
	if (!pool)
		return 0;
	
	result = GPOINTER_TO_UINT (pool->sessions->data);
	g_assert (result != 0);
	pool->sessions = g_slist_remove (pool->sessions, pool->sessions->data);
	
	return result;
}

static void
destroy_session_table (GP11Slot *slot)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	if (pv->open_sessions)
		g_hash_table_unref (pv->open_sessions);
	pv->open_sessions = NULL;
}

static void
create_session_table (GP11Slot *slot)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	if (!pv->open_sessions)
		pv->open_sessions = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, free_session_pool);
}

static void
reuse_session_handle (GP11Session *session, GP11Slot *slot)
{
	CK_SESSION_INFO info;
	guint flags;
	CK_RV rv;
	
	g_return_if_fail (GP11_IS_SESSION (session));
	g_return_if_fail (GP11_IS_SLOT (slot));
	g_return_if_fail (GP11_IS_MODULE (slot->module));
	g_return_if_fail (session->handle != 0);
	
	/* Get the session info so we know where to categorize this */
	rv = (slot->module->funcs->C_GetSessionInfo) (session->handle, &info);
	
	/* An already closed session, we don't want to bother with */
	if (rv == CKR_SESSION_CLOSED || rv == CKR_SESSION_HANDLE_INVALID) {
		session->handle = 0;
		return;
	}
	
	/* A strange session, let it go to be closed somewhere else */
	if (rv != CKR_OK)
		return;
	
	/* 
	 * Get the flags that this session was opened with originally, and
	 * check them against the session's current flags. If they're no
	 * longer present, then don't reuse this session.
	 */
	flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (session), 
	                                             "gp11-open-session-flags"));
	if ((flags & info.flags) != flags)
		return;
	
	/* Keep this one around for later use */
	push_session_table (slot, flags, session->handle);
	session->handle = 0;
}

static GP11Session*
make_session_object (GP11Slot *slot, guint flags, CK_SESSION_HANDLE handle)
{
	GP11Session *session;
	
	g_return_val_if_fail (handle != 0, NULL);
	session = gp11_session_from_handle (slot, handle);
	g_return_val_if_fail (session != NULL, NULL);
	
	/* Session keeps a reference to us, so this is safe */
	g_signal_connect (session, "discard-handle", G_CALLBACK (reuse_session_handle), slot);

	/* Mark the flags on the session for later looking up */
	g_object_set_data (G_OBJECT (session), "gp11-open-session-flags", GUINT_TO_POINTER (flags));
	
	return session;
}

static void 
ensure_token_info (GP11Slot *slot)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	if (!pv->token_info) 
		pv->token_info = gp11_slot_get_token_info (slot);
}

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
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (obj);
	GP11Slot *slot = GP11_SLOT (obj);

	switch (prop_id) {
	case PROP_MODULE:
		g_value_set_object (value, slot->module);
		break;
	case PROP_HANDLE:
		g_value_set_uint (value, slot->handle);
		break;
	case PROP_AUTO_LOGIN:
		g_value_set_boolean (value, pv->auto_login);
		break;
	case PROP_REUSE_SESSIONS:
		g_value_set_boolean (value, pv->open_sessions != NULL);
		break;
	}
}

static void
gp11_slot_set_property (GObject *obj, guint prop_id, const GValue *value, 
                        GParamSpec *pspec)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (obj);
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
	case PROP_AUTO_LOGIN:
		pv->auto_login = g_value_get_boolean (value);
		break;
	case PROP_REUSE_SESSIONS:
		if (g_value_get_boolean (value))
			create_session_table (slot);
		else
			destroy_session_table (slot);
		break;
	}
}

static void
gp11_slot_dispose (GObject *obj)
{
	GP11Slot *slot = GP11_SLOT (obj);

	/* Need to do this before the module goes away */
	destroy_session_table (slot);

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

	g_object_class_install_property (gobject_class, PROP_AUTO_LOGIN,
		g_param_spec_boolean ("auto-login", "Auto Login", "Auto Login to Token when necessary",
		                      FALSE, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_REUSE_SESSIONS,
		g_param_spec_boolean ("reuse-sessions", "Reuse Sessions", "Reuse sessions?",
		                      FALSE, G_PARAM_READWRITE));
	
	signals[AUTHENTICATE_TOKEN] = g_signal_new ("authenticate-token", GP11_TYPE_SLOT, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GP11SlotClass, authenticate_token),
			g_signal_accumulator_true_handled, NULL, _gp11_marshal_BOOLEAN__POINTER, 
			G_TYPE_BOOLEAN, 1, G_TYPE_POINTER);

	g_type_class_add_private (gobject_class, sizeof (GP11SlotPrivate));
}

/* ----------------------------------------------------------------------------
 * INTERNAL
 */

gboolean 
_gp11_slot_token_authentication (GP11Slot *slot, gchar **password)
{
	GP11SlotPrivate *pv = GP11_SLOT_GET_PRIVATE (slot);
	gboolean ret = FALSE;
	
	g_return_val_if_fail (GP11_IS_SLOT (slot), FALSE);
	g_return_val_if_fail (password, FALSE);
	
	if (!pv->auto_login)
		return FALSE;

	/* 
	 * If it's a protected authentication path style token, then 
	 * we don't prompt here, the hardware/software is expected
	 * to prompt the user in some other way.
	 */
	ensure_token_info (slot);
	if (pv->token_info && (pv->token_info->flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		*password = NULL;
		return TRUE;
	}
		
	g_signal_emit (slot, signals[AUTHENTICATE_TOKEN], 0, password, &ret);
	return ret;
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

CK_SLOT_ID
gp11_slot_get_handle (GP11Slot *slot)
{
	g_return_val_if_fail (GP11_IS_SLOT (slot), (CK_SLOT_ID)-1);
	return slot->handle;
}

gboolean
gp11_slot_get_reuse_sessions (GP11Slot *slot)
{
	gboolean reuse = FALSE;
	g_object_get (slot, "reuse-sessions", &reuse, NULL);
	return reuse;
}

void
gp11_slot_set_reuse_sessions (GP11Slot *slot, gboolean reuse)
{
	g_object_set (slot, "reuse-sessions", reuse, NULL);
}

gboolean
gp11_slot_get_auto_login (GP11Slot *slot)
{
	gboolean auto_login = FALSE;
	g_object_get (slot, "auto-login", &auto_login, NULL);
	return auto_login;
}

void
gp11_slot_set_auto_login (GP11Slot *slot, gboolean auto_login)
{
	g_object_set (slot, "auto-login", auto_login, NULL);
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
	CK_SESSION_HANDLE handle;
	
	/* Try to use a cached session */
	handle = pop_session_table (slot, flags);
	if (handle != 0)
		return make_session_object (slot, flags, handle);
	
	/* Open a new session */
	if (!_gp11_call_sync (slot, perform_open_session, &args, cancellable, err))
		return FALSE;
	
	return make_session_object (slot, flags, args.session);
}

void
gp11_slot_open_session_async (GP11Slot *slot, guint flags, GCancellable *cancellable, 
                              GAsyncReadyCallback callback, gpointer user_data)
{
	OpenSession *args = _gp11_call_async_prep (slot, perform_open_session,
	                                           sizeof (*args), NULL);
	
	/* Try to use a cached session */
	args->session = pop_session_table (slot, flags);
	args->flags = flags;
	
	if (args->session)
		_gp11_call_async_short (args, callback, user_data);
	else
		_gp11_call_async_go (args, cancellable, callback, user_data);
}

GP11Session*
gp11_slot_open_session_finish (GP11Slot *slot, GAsyncResult *result, GError **err)
{
	OpenSession *args;
	
	if (!_gp11_call_basic_finish (slot, result, err))
		return NULL;
	
	args = _gp11_call_arguments (result, OpenSession);
	return make_session_object (slot, args->flags, args->session);
}
