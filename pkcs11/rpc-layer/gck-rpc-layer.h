#ifndef GCKRPC_H_
#define GCKRPC_H_

#include "pkcs11/pkcs11.h"

/* ------------------------------------------------------------------
 * DISPATCHER 
 */

/* Call to initialize the module and start listening, returns socket or -1 */
int                gck_rpc_dispatch_init                (const char *socket_prefix, 
                                                         CK_FUNCTION_LIST_PTR module, 
                                                         CK_C_INITIALIZE_ARGS_PTR init_args);

/* Should be called to cleanup dispatcher */
void               gck_rpc_dispatch_uninit              (void);

/* Accept a new connection. Should be called when above fd has read */
void               gck_rpc_dispatch_accept              (void);

#endif /* GCKRPC_H_ */
