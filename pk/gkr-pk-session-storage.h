#ifndef __GKR_PK_SESSION_STORAGE_H__
#define __GKR_PK_SESSION_STORAGE_H__

#include <glib-object.h>

#include "pk/gkr-pk-storage.h"

G_BEGIN_DECLS

#define GKR_TYPE_PK_SESSION_STORAGE             (gkr_pk_session_storage_get_type ())
#define GKR_PK_SESSION_STORAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_SESSION_STORAGE, GkrPkSessionStorage))
#define GKR_PK_SESSION_STORAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_SESSION_STORAGE, GObject))
#define GKR_IS_PK_SESSION_STORAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_SESSION_STORAGE))
#define GKR_IS_PK_SESSION_STORAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_SESSION_STORAGE))
#define GKR_PK_SESSION_STORAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_SESSION_STORAGE, GkrPkSessionStorageClass))

typedef struct _GkrPkSessionStorage GkrPkSessionStorage;
typedef struct _GkrPkSessionStorageClass GkrPkSessionStorageClass;

struct _GkrPkSessionStorage {
	 GkrPkStorage parent;
	 GkrPkIndex *index;
};

struct _GkrPkSessionStorageClass {
	GkrPkStorageClass parent_class;
};

GType                   gkr_pk_session_storage_get_type          (void) G_GNUC_CONST;

GkrPkSessionStorage*    gkr_pk_session_storage_new               (void);

G_END_DECLS

#endif /* __GKR_PK_SESSION_STORAGE_H__ */
