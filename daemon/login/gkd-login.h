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

#ifndef __GKD_LOGIN_H__
#define __GKD_LOGIN_H__

#include <glib.h>

typedef struct _GckSession GckSession;

gboolean          gkd_login_unlock                   (const gchar *master);

gboolean          gkd_login_change_lock              (const gchar *original,
                                                      const gchar *master);

gboolean          gkd_login_available                (GckSession *session);

gchar *           gkd_login_lookup_password          (GckSession *session,
						      const gchar *field,
						      ...) G_GNUC_NULL_TERMINATED;

void              gkd_login_clear_password           (GckSession *session,
						      const gchar *field,
						      ...) G_GNUC_NULL_TERMINATED;

gboolean          gkd_login_store_password           (GckSession *session,
						      const gchar *password,
						      const gchar *label,
						      const gchar *method,
						      gint lifetime,
						      const gchar *field,
						      ...) G_GNUC_NULL_TERMINATED;

gchar *           gkd_login_lookup_passwordv         (GckSession *session,
						      GHashTable *fields);

void              gkd_login_clear_passwordv          (GckSession *session,
						      GHashTable *fields);

gboolean          gkd_login_store_passwordv          (GckSession *session,
						      const gchar *password,
						      const gchar *label,
						      const gchar *method,
						      gint lifetime,
						      GHashTable *fields);

#endif /* __GKD_LOGIN_H__ */
