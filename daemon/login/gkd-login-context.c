#include "config.h"
#include "gkd-login-context.h"

struct _GkdLoginContext {
	GObject parent_instance;
};

enum {
	KEYRING_CREATED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GkdLoginContext, gkd_login_context, G_TYPE_OBJECT)

static void
gkd_login_context_class_init (GkdLoginContextClass *klass)
{
	/* * keyring-created signal:
	 * Emitted when the login keyring is successfully created on disk/in the store.
	 * Passes the GckObject representing the keyring so subscribers can use it.
	 */
	signals[KEYRING_CREATED] = g_signal_new ("keyring-created",
	                                         GKD_TYPE_LOGIN_CONTEXT,
	                                         G_SIGNAL_RUN_LAST,
	                                         0,
	                                         NULL, NULL,
	                                         g_cclosure_marshal_VOID__OBJECT,
	                                         G_TYPE_NONE,
	                                         1, GCK_TYPE_OBJECT);
}

static void
gkd_login_context_init (GkdLoginContext *self)
{
}

GkdLoginContext *
gkd_login_context_get_default (void)
{
	static GkdLoginContext *default_login_context = NULL;

	if (g_once_init_enter_pointer (&default_login_context)) {
		GkdLoginContext *context = g_object_new (GKD_TYPE_LOGIN_CONTEXT, NULL);

		g_once_init_leave_pointer (&default_login_context, context);
	}

	return default_login_context;
}

void
gkd_login_context_emit_keyring_created (GkdLoginContext *self,
                                        GckObject       *keyring)
{
	g_return_if_fail (GKD_IS_LOGIN_CONTEXT (self));
	g_return_if_fail (GCK_IS_OBJECT (keyring));

	g_signal_emit (self, signals[KEYRING_CREATED], 0, keyring);
}
