/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef __GKD_PROMPT_H__
#define __GKD_PROMPT_H__

#include <glib-object.h>

#include <gp11/gp11.h>

typedef enum {
	GKD_RESPONSE_FAILURE      = -1,
	GKD_RESPONSE_NONE         = 0,
	GKD_RESPONSE_NO           = 1,
	GKD_RESPONSE_OK           = 2,
	GKD_RESPONSE_OTHER        = 3,
} GkrAskResponse;

#define GKD_TYPE_PROMPT               (gkd_prompt_get_type ())
#define GKD_PROMPT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_TYPE_PROMPT, GkdPrompt))
#define GKD_PROMPT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_TYPE_PROMPT, GkdPromptClass))
#define GKD_IS_PROMPT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_TYPE_PROMPT))
#define GKD_IS_PROMPT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_TYPE_PROMPT))
#define GKD_PROMPT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_TYPE_PROMPT, GkdPromptClass))

typedef struct _GkdPrompt GkdPrompt;
typedef struct _GkdPromptClass GkdPromptClass;
typedef struct _GkdPromptPrivate GkdPromptPrivate;

struct _GkdPrompt {
	GObject parent;
	GkdPromptPrivate *pv;
};

struct _GkdPromptClass {
	GObjectClass parent_class;

	/* signals */
	gboolean (*responded) (GkdPrompt *self);
	void (*completed) (GkdPrompt *self);
};

GType               gkd_prompt_get_type               (void);

GkdPrompt*          gkd_prompt_new                    (void);

void                gkd_prompt_reset                  (GkdPrompt *prompt,
                                                       gboolean hard);

void                gkd_prompt_set_title              (GkdPrompt *prompt,
                                                       const gchar *title);

void                gkd_prompt_set_primary_text       (GkdPrompt *prompt,
                                                       const gchar *primary);

void                gkd_prompt_set_secondary_text     (GkdPrompt *prompt,
                                                       const gchar *secondary);

void                gkd_prompt_set_warning            (GkdPrompt *prompt,
                                                       const gchar *warning);

void                gkd_prompt_set_window_id          (GkdPrompt *prompt,
                                                       const gchar *window_id);

void                gkd_prompt_show_widget            (GkdPrompt *prompt,
                                                       const gchar *widget);

void                gkd_prompt_hide_widget            (GkdPrompt *prompt,
                                                       const gchar *widget);

void                gkd_prompt_select_widget          (GkdPrompt *prompt,
                                                       const gchar *widget);

gboolean            gkd_prompt_has_response           (GkdPrompt *prompt);

gint                gkd_prompt_get_response           (GkdPrompt *prompt);

gchar*              gkd_prompt_get_password           (GkdPrompt *prompt,
                                                       const gchar *password_type);

gpointer            gkd_prompt_get_transport_param    (GkdPrompt *prompt,
                                                       const gchar *name,
                                                       gsize *n_value);

void                gkd_prompt_set_transport_param    (GkdPrompt *prompt,
                                                       const gchar *name,
                                                       gconstpointer value,
                                                       gsize n_value);

gboolean            gkd_prompt_get_transport_password (GkdPrompt *self,
                                                       const gchar *password_type,
                                                       gpointer *parameter,
                                                       gsize *n_parameter,
                                                       gpointer *value,
                                                       gsize *n_value);

void                gkd_prompt_get_unlock_options     (GkdPrompt *self,
                                                       GP11Attributes *attrs);

void                gkd_prompt_set_unlock_options     (GkdPrompt *self,
                                                       GP11Attributes *attrs);

gboolean            gkd_prompt_is_widget_selected     (GkdPrompt *prompt,
                                                       const gchar *widget);

typedef GkdPrompt*  (*GkdPromptAttentionFunc)             (gpointer user_data);

void                gkd_prompt_request_attention_async    (const gchar *window_id,
                                                           GkdPromptAttentionFunc callback,
                                                           gpointer user_data,
                                                           GDestroyNotify destroy_notify);

void                gkd_prompt_request_attention_sync     (const gchar *window_id,
                                                           GkdPromptAttentionFunc callback,
                                                           gpointer user_data,
                                                           GDestroyNotify destroy_notify);

#endif /* __GKD_PROMPT_H__ */
