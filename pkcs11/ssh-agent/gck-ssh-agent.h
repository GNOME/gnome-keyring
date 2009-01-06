#ifndef GCKSSHAGENT_H_
#define GCKSSHAGENT_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

int               gck_ssh_agent_initialize              (const gchar *prefix, CK_FUNCTION_LIST_PTR funcs);

void              gck_ssh_agent_accept                  (void);

void              gck_ssh_agent_uninitialize            (void);

#endif /* GCKSSHAGENT_H_ */
