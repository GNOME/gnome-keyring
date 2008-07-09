/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-index.h - indexes to store values related to pk objects

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRPKINDEX_H_
#define GKRPKINDEX_H_

#include <glib.h>

#include "common/gkr-id.h"

#include "keyrings/gkr-keyring.h"

#include "library/gnome-keyring.h"

#define GKR_TYPE_PK_INDEX             (gkr_pk_index_get_type())
#define GKR_PK_INDEX(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GKR_TYPE_PK_INDEX, GkrPkIndex))
#define GKR_IS_PK_INDEX(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GKR_TYPE_PK_INDEX))

typedef struct _GkrPkIndex      GkrPkIndex;
typedef struct _GkrPkIndexClass GkrPkIndexClass;

struct _GkrPkIndex {
	 GObject parent;
	 GkrKeyring *keyring;
	 gboolean denied;
	 GnomeKeyringAttributeList *defaults;
};

struct _GkrPkIndexClass {
	GObjectClass parent_class;
};

GType               gkr_pk_index_get_type              (void);

GkrPkIndex*         gkr_pk_index_new                   (GkrKeyring* keyring, 
                                                        GnomeKeyringAttributeList *defaults);

GkrPkIndex*         gkr_pk_index_open                  (GQuark index_location, const gchar *name, 
                                                        GnomeKeyringAttributeList *defaults);

GkrPkIndex*         gkr_pk_index_default               (void);

gboolean            gkr_pk_index_get_boolean           (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, gboolean defvalue);

guint               gkr_pk_index_get_uint              (GkrPkIndex *index, gkrconstid digest, 
                                                        const gchar *field, guint defvalue);
                                                                  
gchar*              gkr_pk_index_get_string            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field);

gchar*              gkr_pk_index_get_secret            (GkrPkIndex *index, gkrconstid digest);

guchar*             gkr_pk_index_get_binary            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, gsize *n_data);
                                                        
GQuark*             gkr_pk_index_get_quarks            (GkrPkIndex *index, gkrconstid digest, 
                                                        const gchar *field);

gboolean            gkr_pk_index_set_boolean           (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, gboolean val);

gboolean            gkr_pk_index_set_uint              (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, guint val);
                                                        
gboolean            gkr_pk_index_set_string            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, const gchar *val);

gboolean            gkr_pk_index_set_secret            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *secret);

gboolean            gkr_pk_index_set_binary            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, const guchar *data, 
                                                        gsize n_data);

gboolean            gkr_pk_index_set_quarks            (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field, GQuark *quarks);

gboolean            gkr_pk_index_has_value             (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field);

gboolean            gkr_pk_index_clear                 (GkrPkIndex *index, gkrconstid digest,
                                                        const gchar *field);

gboolean            gkr_pk_index_rename                (GkrPkIndex *index, gkrconstid old_digest, 
                                                        gkrconstid new_digest);

gboolean            gkr_pk_index_copy                  (GkrPkIndex *old_index, GkrPkIndex *new_index,
                                                        gkrconstid digest);

gboolean            gkr_pk_index_delete                (GkrPkIndex *index, gkrconstid digest);

gboolean            gkr_pk_index_have                  (GkrPkIndex *index, gkrconstid digest);


/* -----------------------------------------------------------------------------
 * LISTS OF QUARKS
 */

gboolean            gkr_pk_index_quarks_has            (GQuark *quarks, GQuark check);

GQuark*             gkr_pk_index_quarks_dup            (GQuark *quarks);

void                gkr_pk_index_quarks_free           (GQuark *quarks);

#endif /*GKRPKINDEX_H_*/
