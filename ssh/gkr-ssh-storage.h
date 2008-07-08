#ifndef __GKR_SSH_STORAGE_H__
#define __GKR_SSH_STORAGE_H__

#include <glib-object.h>

#include "pk/gkr-pk-storage.h"

#include "pkix/gkr-pkix-types.h"

G_BEGIN_DECLS

#define GKR_TYPE_SSH_STORAGE             (gkr_ssh_storage_get_type ())
#define GKR_SSH_STORAGE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_SSH_STORAGE, GkrSshStorage))
#define GKR_SSH_STORAGE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_SSH_STORAGE, GObject))
#define GKR_IS_SSH_STORAGE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_SSH_STORAGE))
#define GKR_IS_SSH_STORAGE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_SSH_STORAGE))
#define GKR_SSH_STORAGE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_SSH_STORAGE, GkrSshStorageClass))

typedef struct _GkrSshStorage GkrSshStorage;
typedef struct _GkrSshStorageClass GkrSshStorageClass;

struct _GkrSshStorage {
	 GkrPkStorage parent;
};

struct _GkrSshStorageClass {
	GkrPkStorageClass parent_class;
};

GType                   gkr_ssh_storage_get_type          (void) G_GNUC_CONST;

gboolean                gkr_ssh_storage_initialize        (void);

GkrPkixResult           gkr_ssh_storage_load_public_key   (const guchar *data, gsize n_data, 
                                                           gcry_sexp_t *sexp, gchar **comment);

guchar*                 gkr_ssh_storage_write_public_key  (gcry_sexp_t sexp, const gchar *comment,
                                                           gsize *n_data);

G_END_DECLS

#endif /* __GKR_SSH_STORAGE_H__ */
