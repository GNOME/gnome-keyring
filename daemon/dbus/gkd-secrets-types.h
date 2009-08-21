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

#ifndef __GKD_SECRETS_TYPES_H__
#define __GKD_SECRETS_TYPES_H__

#define BUS_INTERFACE                  "org.freedesktop.DBus"
#define PROPERTIES_INTERFACE           "org.freedesktop.DBus.Properties"

#define SECRETS_SERVICE_INTERFACE      "org.freedesktop.Secrets.Service"
#define SECRETS_SERVICE_PATH           "/org/freedesktop/secrets"
#define SECRETS_SERVICE                "org.freedesktop.secrets"

#define SECRETS_COLLECTION_PREFIX      "/org/freedesktop/secrets/collection"

#define SECRETS_SESSION_PREFIX         "/org/freedesktop/secrets/session"

#define SECRETS_ERROR_ALREADY_EXISTS   "org.freedesktop.Secrets.Error.AlreadyExists"
#define SECRETS_ERROR_IS_LOCKED        "org.freedesktop.Secrets.Error.IsLocked"
#define SECRETS_ERROR_NOT_SUPPORTED    "org.freedesktop.Secrets.Error.NotSupported"
#define SECRETS_ERROR_NO_SESSION       "org.freedesktop.Secrets.Error.NoSession"

typedef struct _GkdSecretsCollection GkdSecretsCollection;
typedef struct _GkdSecretsItem GkdSecretsItem;
typedef struct _GkdSecretsService GkdSecretsService;
typedef struct _GkdSecretsSession GkdSecretsSession;

#endif /* __GKD_SECRETS_TYPES_H__ */
