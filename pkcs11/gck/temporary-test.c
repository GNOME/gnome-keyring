
#include "gck-crypto.h"

#include <stdlib.h>
#include <pthread.h>

#include "common/gkr-secure-memory.h"

static pthread_mutex_t memory_mutex = PTHREAD_MUTEX_INITIALIZER;

void
gkr_memory_lock (void)
{
	pthread_mutex_lock (&memory_mutex);
}

void
gkr_memory_unlock (void)
{
	pthread_mutex_unlock (&memory_mutex);
}

void*
gkr_memory_fallback (void *p, unsigned long sz)
{
	return realloc (p, sz);
}

int 
main(int argc, char* argv[])
{
	gck_crypto_perform (NULL, 0, 0, NULL, 0, NULL, NULL);
	return 0;
}
