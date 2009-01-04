#ifndef P11RPC_H_
#define P11RPC_H_

#include "pkcs11/pkcs11.h"

#include <stdarg.h>

/* ------------------------------------------------------------------
 * MODULE
 */

/* IMPLEMENT: These functions must be implemented by glue code */

extern void  p11_rpc_log (const char *line);

extern const char* p11_rpc_module_init (CK_C_INITIALIZE_ARGS_PTR init_args);

extern void  p11_rpc_module_uninit (void);

extern int   p11_rpc_write_credentials (int socket);


/* ------------------------------------------------------------------
 * DISPATCHER 
 */

/* Call to initialize the module and start listening on the socket */
int                p11_rpc_dispatch_init                (const char *socket_prefix, 
                                                         CK_FUNCTION_LIST_PTR module, 
                                                         CK_C_INITIALIZE_ARGS_PTR init_args);

/* Should be called to cleanup dispatcher */
void               p11_rpc_dispatch_uninit              (void);

/* Get socket that the dispatcher is listening on, for select */
int                p11_rpc_dispatch_fd                  (void);

/* Accept a new connection. Should be called when above fd has read */
void               p11_rpc_dispatch_accept              (void);


/* IMPLEMENT: These functions must be implemented by glue code */

extern void        p11_rpc_log                          (const char *line);

extern void*       p11_rpc_create_child                 (void (*child_func) (void*),
                                                         void* child_arg);

extern void        p11_rpc_join_child                   (void *child);

extern int         p11_rpc_read_credentials             (int socket);

#endif /* P11RPC_H_ */
