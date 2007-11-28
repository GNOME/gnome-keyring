#ifndef GKRMASTERDIRECTORY_H_
#define GKRMASTERDIRECTORY_H_

#include <glib.h>

const gchar*    gkr_daemon_util_get_master_directory    (void);

void            gkr_daemon_util_push_environment        (const gchar *name, const gchar *value);

const gchar*    gkr_daemon_util_get_environment         (void);

#endif /*GKRMASTERDIRECTORY_H_*/
