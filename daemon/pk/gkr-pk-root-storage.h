#ifndef __GKR_PK_ROOT_STORAGE_H__
#define __GKR_PK_ROOT_STORAGE_H__

#include <glib-object.h>

#include "pk/gkr-pk-storage.h"

#include "pkix/gkr-pkix-types.h"

G_BEGIN_DECLS

#define GKR_TYPE_PK_ROOT_STORAGE             (gkr_pk_root_storage_get_type ())
#define GKR_PK_ROOT_STORAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_ROOT_STORAGE, GkrPkRootStorage))
#define GKR_PK_ROOT_STORAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_ROOT_STORAGE, GObject))
#define GKR_IS_PK_ROOT_STORAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_ROOT_STORAGE))
#define GKR_IS_PK_ROOT_STORAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_ROOT_STORAGE))
#define GKR_PK_ROOT_STORAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_ROOT_STORAGE, GkrPkRootStorageClass))

typedef struct _GkrPkRootStorage GkrPkRootStorage;
typedef struct _GkrPkRootStorageClass GkrPkRootStorageClass;

struct _GkrPkRootStorage {
	 GkrPkStorage parent;
};

struct _GkrPkRootStorageClass {
	GkrPkStorageClass parent_class;
};

GType                   gkr_pk_root_storage_get_type          (void) G_GNUC_CONST;

gboolean                gkr_pk_root_storage_initialize        (void);

G_END_DECLS

#endif /* __GKR_PK_ROOT_STORAGE_H__ */
