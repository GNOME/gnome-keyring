/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-session.c - Represents a PK session

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

#include "config.h"

#include "gkr-pk-manager.h"
#include "gkr-pk-session.h"
#include "gkr-pk-session-storage.h"
#include "gkr-pk-storage.h"

/* --------------------------------------------------------------------------------
 * DECLARATIONS
 */

enum {
	PROP_0,
	PROP_MANAGER,
	PROP_STORAGE
};

G_DEFINE_TYPE(GkrPkSession, gkr_pk_session, G_TYPE_OBJECT);

/* --------------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_session_init (GkrPkSession *session)
{

}

static void
gkr_pk_session_get_property (GObject *obj, guint prop_id, GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkSession *session = GKR_PK_SESSION (obj);

	switch (prop_id) {
	case PROP_MANAGER:
		g_value_set_object (value, session->manager);
		break;
	case PROP_STORAGE:
		g_value_set_object (value, session->storage);
		break;
	}
}

static void
gkr_pk_session_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GkrPkSession *session = GKR_PK_SESSION (obj);
	
	switch (prop_id) {
	case PROP_MANAGER:
		g_assert (!session->manager);
		session->manager = g_value_get_object (value);
		g_return_if_fail (session->manager);
		g_object_ref (session->manager);
		break; 
		
	case PROP_STORAGE:
		g_assert (!session->storage);
		session->storage = g_value_get_object (value);
		g_return_if_fail (session->storage);
		g_object_ref (session->storage);
		break;
	};
}
                                    
static void
gkr_pk_session_finalize (GObject *obj)
{
	GkrPkSession *session = GKR_PK_SESSION (obj);

	if (session->storage)
		g_object_unref (session->storage);
	session->storage = NULL;
	
	if (session->manager)
		g_object_unref (session->manager);
	session->manager = NULL;
	
	G_OBJECT_CLASS (gkr_pk_session_parent_class)->finalize (obj);
}

static void
gkr_pk_session_class_init (GkrPkSessionClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*) klass;

	gkr_pk_session_parent_class = g_type_class_peek_parent (klass);
	gobject_class->get_property = gkr_pk_session_get_property;
	gobject_class->set_property = gkr_pk_session_set_property;
	gobject_class->finalize = gkr_pk_session_finalize;
	
	g_object_class_install_property (gobject_class, PROP_MANAGER, 
		g_param_spec_object ("manager", "Manager", "Object Manager for Session",
		                     GKR_TYPE_PK_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_STORAGE,
		g_param_spec_object ("storage", "Storage", "Storage for Session",
		                     GKR_TYPE_PK_STORAGE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* --------------------------------------------------------------------------------
 * PUBLIC 
 */
 
GkrPkSession*
gkr_pk_session_new (void)
{
	return gkr_pk_session_new_for_client (0);
}

GkrPkSession*
gkr_pk_session_new_for_client (pid_t pid)
{
	GkrPkStorage *storage;
	GkrPkManager *manager;
	GkrPkSession *session;
	
	storage = GKR_PK_STORAGE (gkr_pk_session_storage_new ());
	if (pid == 0)
		manager = gkr_pk_manager_new ();
	else
		manager = gkr_pk_manager_instance_for_client(pid);
	
	session = g_object_new (GKR_TYPE_PK_SESSION, "manager", manager, "storage", storage, NULL);
	
	g_object_unref (manager);
	g_object_unref (storage);
	
	return session;
}
