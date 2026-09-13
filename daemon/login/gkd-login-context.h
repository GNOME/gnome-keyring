#ifndef GKD_LOGIN_CONTEXT_H
#define GKD_LOGIN_CONTEXT_H

#include <glib-object.h>
#include <gck/gck.h>

#define GKD_TYPE_LOGIN_CONTEXT (gkd_login_context_get_type ())
G_DECLARE_FINAL_TYPE (GkdLoginContext, gkd_login_context, GKD, LOGIN_CONTEXT, GObject)

/* Singleton accessor */
GkdLoginContext * gkd_login_context_get_default          (void);

/* Trigger to be called by gkd-login.c when the keyring is ready */
void              gkd_login_context_emit_keyring_created (GkdLoginContext *self,
                                                          GckObject       *keyring);

#endif /* GKD_LOGIN_CONTEXT_H */
