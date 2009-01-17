
#include <glib.h>

#include "egg/egg-secure-memory.h"
 
/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
egg_memory_lock (void)
{

}

void 
egg_memory_unlock (void)
{

}

void*
egg_memory_fallback (void *p, unsigned long sz)
{
	return g_realloc (p, sz);
}
