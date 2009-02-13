#ifndef GCKDATA_H_
#define GCKDATA_H_

#include <glib.h>

typedef enum _GckDataResult {
	GCK_DATA_FAILURE = -2,
	GCK_DATA_LOCKED = -1, 
	GCK_DATA_UNRECOGNIZED = 0,
	GCK_DATA_SUCCESS = 1
} GckDataResult;

#define  GCK_DATA_ERROR      (g_quark_from_static_string ("gck-data-error"))

#endif /* GCKDATA_H_ */
