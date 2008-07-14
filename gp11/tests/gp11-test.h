#ifndef TESTGP11HELPERS_H_
#define TESTGP11HELPERS_H_

#include "gp11.h"

#define FAIL_RES(res, e) do { \
	fail_if (res ? TRUE : FALSE, "should have failed"); \
	fail_unless ((e) && (e)->message, "error should be set"); \
	g_clear_error (&e); \
	} while (0)

#define SUCCESS_RES(res, err) do { \
	if (!res) g_printerr ("error: %s\n", err && err->message ? err->message : ""); \
	fail_unless (res ? TRUE : FALSE, "should have succeeded"); \
	g_clear_error (&err); \
	} while(0)


#define WAIT_UNTIL(cond) \
	while(!cond) g_main_iteration (TRUE);

#endif /*TESTGP11HELPERS_H_*/
