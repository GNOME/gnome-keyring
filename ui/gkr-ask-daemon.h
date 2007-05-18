
#ifndef _GKR_ASK_DAEMON_H_
#define _GKR_ASK_DAEMON_H_

#include <glib.h>

#include "gkr-ask-request.h"

void           gkr_ask_daemon_init        (void);

void           gkr_ask_daemon_cleanup     (void);

void           gkr_ask_daemon_queue       (GkrAskRequest* ask);

void           gkr_ask_daemon_cancel      (GkrAskRequest* ask);

void           gkr_ask_daemon_set_display (const gchar* display);

const gchar*   gkr_ask_daemon_get_display (void);

#endif /* _GKR_ASK_DAEMON_H_ */
