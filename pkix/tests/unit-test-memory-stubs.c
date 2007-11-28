
#include <glib.h>

#include "common/gkr-secure-memory.h"
 
/* 
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT;

void
gkr_memory_lock (void)
{
	g_static_mutex_lock (&memory_mutex);
}

void 
gkr_memory_unlock (void)
{
	g_static_mutex_unlock (&memory_mutex);
}

void*
gkr_memory_fallback (void *p, unsigned long sz)
{
	return g_realloc (p, sz);
}
