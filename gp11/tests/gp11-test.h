#ifndef TESTGP11HELPERS_H_
#define TESTGP11HELPERS_H_

#include "gp11.h"

#define FAIL_RES(res, e) do { \
	g_assert ((res) ? FALSE : TRUE); \
	g_assert ((e) && (e)->message && "error should be set"); \
	g_clear_error (&e); \
	} while (0)

#define SUCCESS_RES(res, err) do { \
	if (!(res)) g_printerr ("error: %s\n", err && err->message ? err->message : ""); \
	g_assert ((res) ? TRUE : FALSE && "should have succeeded"); \
	g_clear_error (&err); \
	} while(0)


#define WAIT_UNTIL(cond) \
	while(!cond) g_main_context_iteration (NULL, TRUE);

/* 
 * Some dumb crypto mechanisms for simple testing.
 * 
 * CKM_CAPITALIZE (encrypt/decrypt)
 *     capitalizes to encrypt
 *     lowercase to decrypt 
 *
 * CKM_PREFIX (sign/verify)
 *     sign prefixes data with key label
 *     verify unprefixes data with key label. 
 */

#define CKM_CAPITALIZE    (CKM_VENDOR_DEFINED | 1)
#define CKM_PREFIX        (CKM_VENDOR_DEFINED | 2)

#endif /*TESTGP11HELPERS_H_*/
