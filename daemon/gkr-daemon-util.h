/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-util.h - Helper utilities for the daemon

   Copyright (C) 2008, Stefan Walter

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

#ifndef GKRMASTERDIRECTORY_H_
#define GKRMASTERDIRECTORY_H_

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#include <sys/types.h>

const gchar*    gkr_daemon_util_get_master_directory    (void);

void            gkr_daemon_util_push_environment        (const gchar *name, const gchar *value);

void            gkr_daemon_util_push_environment_full   (const gchar *env);

const gchar**   gkr_daemon_util_get_environment         (void);

#define GKR_TYPE_DAEMON_CLIENT             (gkr_daemon_client_get_type ())
#define GKR_DAEMON_CLIENT(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_DAEMON_CLIENT, GkrDaemonClient))
#define GKR_DAEMON_CLIENT_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_DAEMON_CLIENT, GkrDaemonClientClass))
#define GKR_IS_DAEMON_CLIENT(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_DAEMON_CLIENT))
#define GKR_IS_DAEMON_CLIENT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_DAEMON_CLIENT))
#define GKR_DAEMON_CLIENT_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_DAEMON_CLIENT, GkrDaemonClientClass))

typedef struct _GkrDaemonClient GkrDaemonClient;
typedef struct _GkrDaemonClientClass GkrDaemonClientClass;

struct _GkrDaemonClient {
	GObject parent;
	pid_t pid;
	gchar *app_path;
	gchar *app_display;
};

struct _GkrDaemonClientClass {
	GObjectClass parent_class;
	void (*disconnected) (GkrDaemonClient *client);
};

GType                             gkr_daemon_client_get_type         (void);

GkrDaemonClient*                  gkr_daemon_client_set_current      (pid_t pid, const gchar *app_path, const gchar *app_display);

GkrDaemonClient*                  gkr_daemon_client_get_current      (void);

pid_t                             gkr_daemon_client_get_app_pid      (GkrDaemonClient* client);

const gchar*                      gkr_daemon_client_get_app_display  (GkrDaemonClient* client);

const gchar*                      gkr_daemon_client_get_app_path     (GkrDaemonClient* client);

G_END_DECLS

#endif /*GKRMASTERDIRECTORY_H_*/
