#ifndef GCKSSHAGENT_H_
#define GCKSSHAGENT_H_

#include <glib.h>

#include "gp11/gp11.h"

gboolean          gck_ssh_agent_initialize              (const gchar *prefix, GP11Slot *slot);

int               gck_ssh_agent_get_socket_fd           (void);

const gchar*      gck_ssh_agent_get_socket_path         (void);

void              gck_ssh_agent_accept                  (void);

void              gck_ssh_agent_uninitialize            (void);

#endif /* GCKSSHAGENT_H_ */
