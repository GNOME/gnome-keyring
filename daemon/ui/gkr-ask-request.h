/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ask-request.c: A single ask request

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

#ifndef __GKR_ASK_REQUEST_H__
#define __GKR_ASK_REQUEST_H__

#include <glib-object.h>

G_BEGIN_DECLS

typedef enum {
	GKR_ASK_RESPONSE_FAILURE                = -1, 
	GKR_ASK_RESPONSE_NONE                   = 0,
	GKR_ASK_RESPONSE_DENY,
	GKR_ASK_RESPONSE_ALLOW,
	GKR_ASK_RESPONSE_ALLOW_FOREVER
} GkrAskResponse;

typedef enum {
	GKR_ASK_REQUEST_PASSWORD                = 0x0001,
	GKR_ASK_REQUEST_CONFIRM_PASSWORD        = 0x0002,
	GKR_ASK_REQUEST_ORIGINAL_PASSWORD       = 0x0004,
	
	GKR_ASK_REQUEST_OK_BUTTON               = 0x0100,
	GKR_ASK_REQUEST_CANCEL_BUTTON           = 0x0200,
	GKR_ASK_REQUEST_CREATE_BUTTON           = 0x0400,
	GKR_ASK_REQUEST_CHANGE_BUTTON           = 0x0800,
	GKR_ASK_REQUEST_ALLOW_BUTTON            = 0x1000,
	GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON    = 0x2000,
	GKR_ASK_REQUEST_DENY_BUTTON             = 0x4000,

	GKR_ASK_REQUEST_BUTTONS_MASK		= 0xFF00
	
} GkrAskRequestFlags;

typedef enum {
	GKR_ASK_DONT_CARE                 = 0,
	GKR_ASK_STOP_REQUEST              = 1,
	GKR_ASK_CONTINUE_REQUEST          = 2
} GkrAskCheckAction;

#define GKR_ASK_REQUEST_OK_DENY_BUTTONS \
	(GKR_ASK_REQUEST_OK_BUTTON | GKR_ASK_REQUEST_DENY_BUTTON)
#define GKR_ASK_REQUEST_OK_CANCEL_BUTTONS \
	(GKR_ASK_REQUEST_OK_BUTTON | GKR_ASK_REQUEST_CANCEL_BUTTON)
#define GKR_ASK_REQUEST_CREATE_CANCEL_BUTTONS \
	(GKR_ASK_REQUEST_CREATE_BUTTON | GKR_ASK_REQUEST_CANCEL_BUTTON)
#define GKR_ASK_REQUEST_CHANGE_CANCEL_BUTTONS \
    (GKR_ASK_REQUEST_CHANGE_BUTTON | GKR_ASK_REQUEST_CANCEL_BUTTON)
#define GKR_ASK_REQUEST_NEW_PASSWORD  \
	(GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_CONFIRM_PASSWORD | GKR_ASK_REQUEST_CREATE_CANCEL_BUTTONS)
#define GKR_ASK_REQUEST_CHANGE_PASSWORD \
    ( GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_CONFIRM_PASSWORD | GKR_ASK_REQUEST_CHANGE_CANCEL_BUTTONS)
#define GKR_ASK_REQUEST_PROMPT_PASSWORD \
	(GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS)
#define GKR_ASK_REQUEST_ACCESS_SOMETHING \
	(GKR_ASK_REQUEST_ALLOW_BUTTON | GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON | GKR_ASK_REQUEST_DENY_BUTTON)

#define GKR_TYPE_ASK_REQUEST             (gkr_ask_request_get_type ())
#define GKR_ASK_REQUEST(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_ASK_REQUEST, GkrAskRequest))
#define GKR_ASK_REQUEST_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_ASK_REQUEST, GObject))
#define GKR_IS_ASK_REQUEST(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_ASK_REQUEST))
#define GKR_IS_ASK_REQUEST_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_ASK_REQUEST))
#define GKR_ASK_REQUEST_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_ASK_REQUEST, GkrAskRequestClass))

typedef struct _GkrAskRequest      GkrAskRequest;
typedef struct _GkrAskRequestClass GkrAskRequestClass;

struct _GkrAskRequest {
	GObject parent;

	/* Results */
	GkrAskResponse response;
	gboolean checked;
	GQuark location_selected;
	gchar* original_password;
	gchar* typed_password;
};

struct _GkrAskRequestClass {
	GObjectClass parent_class;
	
	/* A callback called before and after request to check if still valid */
	GkrAskCheckAction (*check_request) (GkrAskRequest *ask);
};

GType              gkr_ask_request_get_type         (void)G_GNUC_CONST;

GkrAskRequest*     gkr_ask_request_new              (const gchar *title,
                                                     const gchar *primary,
                                                     guint flags);

void               gkr_ask_request_set_secondary    (GkrAskRequest *ask, 
                                                     const gchar *secondary);
                                                     
void               gkr_ask_request_set_check_option (GkrAskRequest *ask,
                                                     const gchar *check_text);

void               gkr_ask_request_set_location_selector (GkrAskRequest *ask,
                                                          gboolean have);
                                                          
void               gkr_ask_request_set_location     (GkrAskRequest *ask,
                                                     GQuark loc);

GObject*           gkr_ask_request_get_object       (GkrAskRequest *ask);

void               gkr_ask_request_set_object       (GkrAskRequest *ask,
                                                     GObject *object);

gboolean           gkr_ask_request_check            (GkrAskRequest *ask);

void               gkr_ask_request_prompt           (GkrAskRequest *ask);

void               gkr_ask_request_deny             (GkrAskRequest *ask);

void               gkr_ask_request_cancel           (GkrAskRequest *ask);

gboolean           gkr_ask_request_is_complete      (GkrAskRequest *ask);

gchar*             gkr_ask_request_make_unique      (GkrAskRequest *ask);

G_END_DECLS

#endif /* __GKR_ASK_REQUEST_H__ */

