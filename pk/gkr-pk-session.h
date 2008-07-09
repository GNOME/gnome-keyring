/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-session.h - Represent a PK session 

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

#ifndef __GKR_PK_SESSION_H__
#define __GKR_PK_SESSION_H__

#include <gcrypt.h>
#include <glib-object.h>

#include "gkr-pk-object.h"
#include "gkr-pk-manager.h"
#include "gkr-pk-storage.h"

G_BEGIN_DECLS

#define GKR_TYPE_PK_SESSION             (gkr_pk_session_get_type ())
#define GKR_PK_SESSION(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PK_SESSION, GkrPkSession))
#define GKR_PK_SESSION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PK_SESSION, GkrPkSession))
#define GKR_IS_PK_SESSION(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PK_SESSION))
#define GKR_IS_PK_SESSION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PK_SESSION))
#define GKR_PK_SESSION_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PK_SESSION, GkrPkSessionClass))

typedef struct _GkrPkSessionClass GkrPkSessionClass;

struct _GkrPkSession {
	 GObject parent;
	 GkrPkStorage *storage;
	 GkrPkManager *manager;
};

struct _GkrPkSessionClass {
	GObjectClass parent_class;
};

GType                   gkr_pk_session_get_type            (void) G_GNUC_CONST;

GkrPkSession*           gkr_pk_session_new                 (void);

GkrPkSession*           gkr_pk_session_new_for_client      (pid_t pid);

G_END_DECLS

#endif /* __GKR_PK_SESSION_H__ */

