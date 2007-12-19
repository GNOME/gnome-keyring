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

#include "common/gkr-unique.h"

gboolean            gkr_pk_index_get_boolean           (GQuark loc, gkrconstunique uni,
                                                        const gchar *field, gboolean defvalue);

gint                gkr_pk_index_get_int               (GQuark loc, gkrconstunique uni,
                                                        const gchar *field, gint defvalue);
                                                                  
gchar*              gkr_pk_index_get_string            (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field);

guchar*             gkr_pk_index_get_binary            (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field, gsize *n_data);
                                                        
GQuark*             gkr_pk_index_get_quarks            (GQuark loc, gkrconstunique unique,
                                                        const gchar *field);

gboolean            gkr_pk_index_set_boolean           (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, gboolean val);

gboolean            gkr_pk_index_set_int               (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, gint val);
                                                        
gboolean            gkr_pk_index_set_string            (GQuark loc, gkrconstunique uni, 
                                                        const gchar *field, const gchar *val);
                                                        
gboolean            gkr_pk_index_set_binary            (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field, const guchar *data,
                                                        gsize n_data);

gboolean            gkr_pk_index_set_quarks            (GQuark loc, gkrconstunique unique,
                                                        const gchar *field, GQuark *quarks);

gboolean            gkr_pk_index_delete                (GQuark loc, gkrconstunique unique, 
                                                        const gchar *field);

/* -----------------------------------------------------------------------------
 * LISTS OF QUARKS
 */

gboolean            gkr_pk_index_quarks_has            (GQuark *quarks, GQuark check);

GQuark*             gkr_pk_index_quarks_dup            (GQuark *quarks);

void                gkr_pk_index_quarks_free           (GQuark *quarks);

#endif /*GKRPKINDEX_H_*/
