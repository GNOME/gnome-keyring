/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-secure-buffer.h - secure memory gtkentry buffer

   Copyright (C) 2009 Stefan Walter

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

#ifndef __GKD_PROMPT_BUFFER_H__
#define __GKD_PROMPT_BUFFER_H__

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define GKD_TYPE_PROMPT_BUFFER            (gkd_prompt_buffer_get_type ())
#define GKD_PROMPT_BUFFER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_TYPE_PROMPT_BUFFER, GkdPromptBuffer))
#define GKD_PROMPT_BUFFER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_TYPE_PROMPT_BUFFER, GkdPromptBufferClass))
#define GKD_IS_PROMPT_BUFFER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_TYPE_PROMPT_BUFFER))
#define GKD_IS_PROMPT_BUFFER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_TYPE_PROMPT_BUFFER))
#define GKD_PROMPT_BUFFER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_TYPE_PROMPT_BUFFER, GkdPromptBufferClass))

typedef struct _GkdPromptBuffer            GkdPromptBuffer;
typedef struct _GkdPromptBufferClass       GkdPromptBufferClass;
typedef struct _GkdPromptBufferPrivate     GkdPromptBufferPrivate;

struct _GkdPromptBuffer
{
	GtkEntryBuffer parent;
	GkdPromptBufferPrivate *priv;
};

struct _GkdPromptBufferClass
{
	GtkEntryBufferClass parent_class;
};

GType                     gkd_prompt_buffer_get_type               (void) G_GNUC_CONST;

GtkEntryBuffer*           gkd_prompt_buffer_new                    (void);

G_END_DECLS

#endif /* __GKD_PROMPT_BUFFER_H__ */
