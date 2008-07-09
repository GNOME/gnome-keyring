
#include <glib.h>

#include "common/gkr-secure-memory.h"
 
/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
gkr_memory_lock (void)
{

}

void 
gkr_memory_unlock (void)
{

}

void*
gkr_memory_fallback (void *p, unsigned long sz)
{
	return g_realloc (p, sz);
}
