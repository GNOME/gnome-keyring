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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __GKD_SECRET_TYPES_H__
#define __GKD_SECRET_TYPES_H__

#define INTERNAL_SERVICE_INTERFACE     "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"

#define SECRET_COLLECTION_INTERFACE    "org.freedesktop.Secret.Collection"
#define SECRET_ITEM_INTERFACE          "org.freedesktop.Secret.Item"
#define SECRET_PROMPT_INTERFACE        "org.freedesktop.Secret.Prompt"
#define SECRET_SERVICE_INTERFACE       "org.freedesktop.Secret.Service"
#define SECRET_SESSION_INTERFACE       "org.freedesktop.Secret.Session"

#define SECRET_SERVICE_PATH            "/org/freedesktop/secrets"
#define SECRET_SERVICE                 "org.freedesktop.secrets"

#define SECRET_INTERFACE_PREFIX        "org.freedesktop.Secret."
#define SECRET_COLLECTION_PREFIX       "/org/freedesktop/secrets/collection"
#define SECRET_SESSION_PREFIX          "/org/freedesktop/secrets/session"
#define SECRET_PROMPT_PREFIX           "/org/freedesktop/secrets/prompt"
#define SECRET_ALIAS_PREFIX            "/org/freedesktop/secrets/aliases"

typedef enum _GkdSecretDaemonError GkdSecretDaemonError;
typedef enum _GkdSecretError GkdSecretError;

typedef struct _GkdSecretCollection GkdSecretCollection;
typedef struct _GkdSecretChange GkdSecretChange;
typedef struct _GkdSecretCreate GkdSecretCreate;
typedef struct _GkdSecretDispatch GkdSecretDispatch;
typedef struct _GkdSecretExchange GkdSecretExchange;
typedef struct _GkdSecretIndex GkdSecretIndex;
typedef struct _GkdSecretItem GkdSecretItem;
typedef struct _GkdSecretObjects GkdSecretObjects;
typedef struct _GkdSecretPrompt GkdSecretPrompt;
typedef struct _GkdSecretSecret GkdSecretSecret;
typedef struct _GkdSecretService GkdSecretService;
typedef struct _GkdSecretSession GkdSecretSession;
typedef struct _GkdSecretUnlock GkdSecretUnlock;

#endif /* __GKD_SECRET_TYPES_H__ */
