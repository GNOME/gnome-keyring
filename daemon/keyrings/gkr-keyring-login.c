/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyrings-login.c - get secrets to automatically unlock keyrings or keys

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

#include "gkr-keyring-login.h"

#include "gkr-keyring.h"
#include "gkr-keyring-item.h"
#include "gkr-keyrings.h"

#include "egg/egg-secure-memory.h"

#include "library/gnome-keyring.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include "util/gkr-location.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>
#include <unistd.h>

gboolean
gkr_keyring_login_is_unlocked (void)
{
	GkrKeyring *login = gkr_keyrings_get_login ();
	return (login && !login->locked);
}

gboolean
gkr_keyring_login_is_usable (void)
{
	/*
	 * We only flag this as usable by our internals if the keyring will
	 * be encrypted when on disk. 
	 */
	GkrKeyring *login = gkr_keyrings_get_login ();
	return (login && !login->locked && !gkr_keyring_is_insecure (login));	
}

static gboolean 
check_ask_request (GkrAskRequest* ask)
{
	GkrKeyring *keyring;
	
	keyring = GKR_KEYRING (gkr_ask_request_get_object (ask));
	g_assert (GKR_IS_KEYRING (keyring));

	if (!keyring->locked) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* If they typed a password, try it out */
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
		
		g_assert (ask->typed_password);
		if (!gkr_keyring_unlock (keyring, ask->typed_password)) {
			/* Bad password, try again */
			ask->response = GKR_ASK_RESPONSE_NONE;
			return GKR_ASK_CONTINUE_REQUEST;
		}
	}
	
	return GKR_ASK_DONT_CARE;
}

static gboolean
request_login_access (GkrKeyring* keyring)
{
	GkrAskRequest *ask;
	gboolean ret;
	
	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Unlock Login Keyring"), _("Enter login password to unlock keyring"),
	                           GKR_ASK_REQUEST_PROMPT_PASSWORD);
	gkr_ask_request_set_secondary (ask, _("Your login keyring was not automatically unlocked when you logged into this computer."));
	gkr_ask_request_set_object (ask, G_OBJECT (keyring));
	
	/* Intercept item access requests to see if we still need to prompt */
	g_signal_connect (ask, "check-request", G_CALLBACK (check_ask_request), NULL);
	
	/* And do the prompt */
	gkr_ask_daemon_process (ask);
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	g_object_unref (ask);
	
	return ret;
}

static gboolean
request_login_new (gchar **password)
{
	GkrAskRequest* ask;
	gboolean ret;
	
	g_assert (password);
	g_assert (!*password);

	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Create Login Keyring"), _("Enter your login password"),
	 	                   GKR_ASK_REQUEST_NEW_PASSWORD);
	gkr_ask_request_set_secondary (ask, _("Your login keyring was not automatically created when you logged "
	                                      "into this computer. It will now be created."));
		               
	/* And do the prompt */
	gkr_ask_daemon_process (ask);
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	if (ret)
		*password = egg_secure_strdup (ask->typed_password);
	g_object_unref (ask);
	return ret;
}

gboolean
gkr_keyring_login_unlock (const gchar *password)
{
	GkrKeyring *login = gkr_keyrings_get_login ();
	gchar *new_password = NULL;
	
	/* Make sure its loaded */
	if (!login) {
		gkr_keyrings_update ();
		login = gkr_keyrings_get_login ();
	}
	
	if (login && !login->locked)
		return TRUE;

	/* Try to unlock the keyring that exists */
	if (login) {
		if (!password)
			return request_login_access (login);
			
		if (!gkr_keyring_unlock (login, password)) {
			g_message ("Couldn't unlock login keyring with provided password");
			return FALSE;
		}
		
		return TRUE; 
	} 
	
	/* No such keyring exists, and we don't have a password. */
	if (!password) {
		if (!request_login_new (&new_password))
			return FALSE;
		g_return_val_if_fail (new_password, FALSE);
		password = new_password;
	}
	
	/* No such keyring exists, so create one */
	login = gkr_keyring_create (GKR_LOCATION_VOLUME_LOCAL, "login", password);
	egg_secure_strfree (new_password);
	
	if (!login) {
		g_warning ("Failed to create login keyring");
		return FALSE;
	}

	g_assert (!login->locked);
	
	gkr_keyrings_add (login);
	g_return_val_if_fail (gkr_keyrings_get_login () == login, FALSE);
	
	g_object_unref (login);
	return TRUE;
}

void
gkr_keyring_login_lock (void)
{
	GkrKeyring *login = gkr_keyrings_get_login ();
	if (login)
		gkr_keyring_lock (login);
}

static GnomeKeyringAttributeList*
string_attribute_list_va (va_list args)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;
	
	attributes = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	
	while ((attribute.name = va_arg (args, char *)) != NULL) {
		attribute.name = g_strdup (attribute.name);
		attribute.value.string = g_strdup (va_arg (args, char *));
		attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
		g_array_append_val (attributes, attribute);
	}
	
	return attributes;
}

const gchar*
gkr_keyring_login_master (void)
{
	GkrKeyring *login;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return NULL;
	
	if (gkr_keyring_is_insecure (login))
		return NULL;
	
	return login->password;
}

void
gkr_keyring_login_attach_secret (GnomeKeyringItemType type, const gchar *display_name, 
                                 const gchar *secret, ...)
{
	GkrKeyring *login;
	GnomeKeyringAttributeList *attrs;
	GkrKeyringItem *item;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return;
		
	va_start (args, secret);
	attrs = string_attribute_list_va (args);
	va_end (args);
	
	item = gkr_keyring_find_item (login, type, attrs, TRUE);
	
	if (!item) {
		item = gkr_keyring_item_create (login, type);
		gkr_keyring_add_item (login, item);
		g_object_unref (item);
	}
	
	g_free (item->display_name);
	item->display_name = g_strdup (display_name); 
	
	egg_secure_strfree (item->secret);
	item->secret = egg_secure_strdup (secret);
	
	gnome_keyring_attribute_list_free (item->attributes);
	item->attributes = attrs;
	
	gkr_keyring_save_to_disk (login);
}

const gchar*
gkr_keyring_login_lookup_secret (GnomeKeyringItemType type, ...)
{
	GkrKeyring *login;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *attrs;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return NULL;

	if (!login->location)
		return NULL;

	va_start (args, type);
	attrs = string_attribute_list_va (args);
	va_end (args);
				
	item = gkr_keyring_find_item (login, type, attrs, TRUE);
	gnome_keyring_attribute_list_free (attrs);
	
	if (item)
		return item->secret;
		
	return NULL;
}
                                                 
void
gkr_keyring_login_remove_secret (GnomeKeyringItemType type, ...)
{
	GkrKeyring *login;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *attrs;
	va_list args;
	
	login = gkr_keyrings_get_login ();
	if (!login || login->locked)
		return;
		
	if (!login->location)
		return;

	va_start (args, type);
	attrs = string_attribute_list_va (args);
	va_end (args);
		
	item = gkr_keyring_find_item (login, type, attrs, TRUE);
	gnome_keyring_attribute_list_free (attrs);
	
	if (item) {
		gkr_keyring_remove_item (login, item);
		gkr_keyring_save_to_disk (login);
	}
}
