#ifndef GCKDATA_H_
#define GCKDATA_H_

#include <glib.h>

typedef enum _GckDataResult {
	GCK_DATA_FAILURE = -2,
	GCK_DATA_UNRECOGNIZED = 0,
	GCK_DATA_SUCCESS = 1
} GckDataResult;

typedef void* (*GckDataAllocator) (void* p, unsigned long len);

#endif /* GCKDATA_H_ */
