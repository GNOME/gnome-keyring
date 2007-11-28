#ifndef GKRPKINDEX_H_
#define GKRPKINDEX_H_


#include <glib.h>

#include "common/gkr-unique.h"

gboolean            gkr_pk_index_get_boolean           (GQuark loc, gkrconstunique uni,
                                                        const gchar *field, gboolean defvalue);

gint                gkr_pk_index_get_int               (GQuark loc, gkrconstunique uni,
                                                        const gchar *field, gint defvalue);
                                                                  
gchar*              gkr_pk_index_get_string            (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field);

guchar*             gkr_pk_index_get_binary            (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field, gsize *n_data);

gboolean            gkr_pk_index_set_boolean           (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, gboolean val);

gboolean            gkr_pk_index_set_int               (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, gint val);
                                                        
gboolean            gkr_pk_index_set_string            (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, const gchar *val);
                                                        
gboolean            gkr_pk_index_set_binary            (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field, const guchar *data,
                                                        gsize n_data);

gboolean            gkr_pk_index_delete                (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field);

#endif /*GKRPKINDEX_H_*/
