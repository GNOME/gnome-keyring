#ifndef GCKSSHAGENT_H_
#define GCKSSHAGENT_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

int               gck_ssh_agent_startup                 (const gchar *prefix);

void              gck_ssh_agent_accept                  (void);

void              gck_ssh_agent_shutdown                (void);

gboolean          gck_ssh_agent_initialize              (CK_FUNCTION_LIST_PTR funcs);

void              gck_ssh_agent_uninitialize            (void);

#endif /* GCKSSHAGENT_H_ */
