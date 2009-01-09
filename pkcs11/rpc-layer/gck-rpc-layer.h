#ifndef GCKRPC_H_
#define GCKRPC_H_

#include "pkcs11/pkcs11.h"

/* ------------------------------------------------------------------
 * DISPATCHER 
 */

/* Call to initialize the module and start listening, returns socket or -1 */
int                gck_rpc_layer_initialize             (const char *prefix, 
                                                         CK_FUNCTION_LIST_PTR funcs);

/* Should be called to cleanup dispatcher */
void               gck_rpc_layer_uninitialize           (void);

/* Accept a new connection. Should be called when above fd has read */
void               gck_rpc_layer_accept                 (void);

#endif /* GCKRPC_H_ */
