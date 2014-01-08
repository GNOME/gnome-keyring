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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __GKM_WRAP_PROMPT_H__
#define __GKM_WRAP_PROMPT_H__

#include <glib-object.h>

#include "pkcs11/pkcs11.h"

typedef struct _GkmWrapPrompt GkmWrapPrompt;

const gchar *       gkm_wrap_prompt_get_prompter_name       (void);

void                gkm_wrap_prompt_set_prompter_name       (const gchar *prompter_name);

GkmWrapPrompt*      gkm_wrap_prompt_for_credential          (CK_FUNCTION_LIST_PTR module,
                                                             CK_SESSION_HANDLE session,
                                                             CK_ATTRIBUTE_PTR template,
                                                             CK_ULONG n_template);

gboolean            gkm_wrap_prompt_do_credential           (GkmWrapPrompt *self,
                                                             CK_ATTRIBUTE_PTR *template,
                                                             CK_ULONG *n_template);

void                gkm_wrap_prompt_done_credential         (GkmWrapPrompt *self,
                                                             CK_RV call_result);

GkmWrapPrompt*      gkm_wrap_prompt_for_init_pin            (CK_FUNCTION_LIST_PTR module,
                                                             CK_SESSION_HANDLE session,
                                                             CK_UTF8CHAR_PTR pin,
                                                             CK_ULONG pin_len);

gboolean            gkm_wrap_prompt_do_init_pin             (GkmWrapPrompt *prompt,
                                                             CK_RV last_result,
                                                             CK_UTF8CHAR_PTR *pin,
                                                             CK_ULONG *n_pin);

void                gkm_wrap_prompt_done_init_pin           (GkmWrapPrompt *prompt,
                                                             CK_RV call_result);

GkmWrapPrompt*      gkm_wrap_prompt_for_set_pin             (CK_FUNCTION_LIST_PTR module,
                                                             CK_SESSION_HANDLE session,
                                                             CK_UTF8CHAR_PTR old_pin,
                                                             CK_ULONG n_old_pin,
                                                             CK_UTF8CHAR_PTR new_pin,
                                                             CK_ULONG n_new_pin);

gboolean            gkm_wrap_prompt_do_set_pin              (GkmWrapPrompt *prompt,
                                                             CK_RV last_result,
                                                             CK_UTF8CHAR_PTR *old_pin,
                                                             CK_ULONG *n_old_pin,
                                                             CK_UTF8CHAR_PTR *new_pin,
                                                             CK_ULONG *n_new_pin);

void                gkm_wrap_prompt_done_set_pin            (GkmWrapPrompt *prompt,
                                                             CK_RV call_result);

GkmWrapPrompt*      gkm_wrap_prompt_for_login               (CK_FUNCTION_LIST_PTR module,
                                                             CK_USER_TYPE user_type,
                                                             CK_SESSION_HANDLE session,
                                                             CK_OBJECT_HANDLE object,
                                                             CK_UTF8CHAR_PTR pin,
                                                             CK_ULONG n_pin);

gboolean            gkm_wrap_prompt_do_login                (GkmWrapPrompt *prompt,
                                                             CK_USER_TYPE user_type,
                                                             CK_RV last_result,
                                                             CK_UTF8CHAR_PTR *pin,
                                                             CK_ULONG *n_pin);

void                gkm_wrap_prompt_done_login              (GkmWrapPrompt *prompt,
                                                             CK_USER_TYPE user_type,
                                                             CK_RV call_result);

#endif /* __GKM_WRAP_PROMPT_H__ */
