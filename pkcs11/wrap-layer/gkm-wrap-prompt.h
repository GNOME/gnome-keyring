/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#ifndef __GKM_WRAP_PROMPT_H__
#define __GKM_WRAP_PROMPT_H__

#include <glib-object.h>

#include "ui/gku-prompt.h"

#define GKM_WRAP_TYPE_PROMPT               (gkm_wrap_prompt_get_type ())
#define GKM_WRAP_PROMPT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKM_WRAP_TYPE_PROMPT, GkmWrapPrompt))
#define GKM_WRAP_PROMPT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKM_WRAP_TYPE_PROMPT, GkmWrapPromptClass))
#define GKM_WRAP_IS_PROMPT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKM_WRAP_TYPE_PROMPT))
#define GKM_WRAP_IS_PROMPT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKM_WRAP_TYPE_PROMPT))
#define GKM_WRAP_PROMPT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKM_WRAP_TYPE_PROMPT, GkmWrapPromptClass))

typedef struct _GkmWrapPrompt GkmWrapPrompt;
typedef struct _GkmWrapPromptClass GkmWrapPromptClass;

struct _GkmWrapPromptClass {
	GkuPromptClass parent_class;
};

GType               gkm_wrap_prompt_get_type                (void);

GkmWrapPrompt*      gkm_wrap_prompt_for_credential          (CK_FUNCTION_LIST_PTR module,
                                                             CK_SESSION_HANDLE session,
                                                             CK_ATTRIBUTE_PTR template,
                                                             CK_ULONG n_template);

gboolean            gkm_wrap_prompt_do_credential           (GkmWrapPrompt *self,
                                                             CK_ATTRIBUTE_PTR *template,
                                                             CK_ULONG *n_template);

void                gkm_wrap_prompt_done_credential         (GkmWrapPrompt *self,
                                                             CK_RV call_result);

#if 0
void                gkm_wrap_prompt_complete                (GkmWrapPrompt *self);

void                gkm_wrap_prompt_dismiss                 (GkmWrapPrompt *self);
#endif

#endif /* __GKM_WRAP_PROMPT_H__ */
