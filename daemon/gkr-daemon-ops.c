/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon.c - main keyring daemon code.

   Copyright (C) 2003 Red Hat, Inc

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

#include "config.h"

#include "gkr-daemon.h"

#include "egg/egg-buffer.h"
#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring.h"
#include "keyrings/gkr-keyring-item.h"
#include "keyrings/gkr-keyrings.h"
#include "keyrings/gkr-keyring-login.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include "ui/gkr-ask-request.h"
#include "ui/gkr-ask-daemon.h"

#include "util/gkr-daemon-util.h"
#include "util/gkr-location.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <locale.h>
#include <sys/types.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>

/* for requesting list access to items */
#define  GNOME_KEYRING_ACCESS_LIST 0

static gboolean
app_ref_match (GnomeKeyringApplicationRef *app1,
	       GnomeKeyringApplicationRef *app2)
{
	if ((app1->display_name != NULL && app2->display_name != NULL) &&
	    strcmp (app1->display_name, app2->display_name) != 0) {
		return FALSE;
	}
	if ((app1->display_name == NULL && app2->display_name != NULL) ||
	    (app1->display_name != NULL && app2->display_name == NULL)) {
		return FALSE;
	}
	
	if ((app1->pathname != NULL && app2->pathname != NULL) &&
	    strcmp (app1->pathname, app2->pathname) != 0) {
		return FALSE;
	}
	if ((app1->pathname == NULL && app2->pathname != NULL) ||
	    (app1->pathname != NULL && app2->pathname == NULL)) {
		return FALSE;
	}
	return TRUE;
}

static GnomeKeyringAccessControl *
acl_find_app (GList *acl, GnomeKeyringApplicationRef *app)
{
	GnomeKeyringAccessControl *ac;
	
	for (; acl != NULL; acl = acl->next) {
		ac = acl->data;
		
		if (app_ref_match (app, ac->application)) {
			return ac;
		}
	}
	
	return NULL;
}

static gboolean
acl_check_access (GkrKeyringItem* item, GnomeKeyringApplicationRef *app, 
                  GnomeKeyringAccessType access_type, gboolean secret)
{
	GnomeKeyringAccessControl *ac;
	GList *l;
	
	/* Any app can list non application-secret items */
	if (access_type == GNOME_KEYRING_ACCESS_LIST) {
		if((item->type & GNOME_KEYRING_ITEM_APPLICATION_SECRET) == 0)
			return TRUE;
	}
	
	/* Any app is allowed to read non-secrets of non application-secret items */
	if (access_type == GNOME_KEYRING_ACCESS_READ && !secret) {
		if ((item->type & GNOME_KEYRING_ITEM_APPLICATION_SECRET) == 0)
			return TRUE;
	}
	
	/* Otherwise look through ACLs */
	for (l = item->acl; l != NULL; l = l->next) {
		ac = l->data;
		if (app_ref_match (app, ac->application) &&
		    (ac->types_allowed & access_type) == access_type) {
			return TRUE;
		}
	}
	
	return FALSE;
}

static void
add_item_acl (GkrKeyringItem *item,
	      GnomeKeyringApplicationRef *app_ref,
	      GnomeKeyringAccessType types_allowed)
{
	GnomeKeyringAccessControl *ac;
	
	ac = acl_find_app (item->acl, app_ref);
	if (ac != NULL) {
		ac->types_allowed |= types_allowed;
	} else {
		ac = gnome_keyring_access_control_new (app_ref,
						       types_allowed);
		item->acl = g_list_prepend (item->acl, ac);
	} 
}

static guint 
check_acl_ask_request (GkrAskRequest* ask, GnomeKeyringApplicationRef *app)
{
	GkrKeyringItem *item;
	gboolean secret;
	GnomeKeyringAccessType access_type;
	
	/* Pull out information from the ask request */
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));
	g_assert (GKR_IS_KEYRING_ITEM (item));
	secret = g_object_get_data (G_OBJECT (ask), "access-secret") ? TRUE : FALSE;
	access_type = (GnomeKeyringAccessType)GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (ask), "access-type")); 
	
	/* Don't deal with straglers */
	if (!item->keyring) {
		ask->response = GKR_ASK_RESPONSE_FAILURE;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* Don't deal with locked keyrings */
	if (item->locked) {
		ask->response = GKR_ASK_RESPONSE_DENY;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* See if this application already has access to this item */
	if (acl_check_access (item, app, access_type, secret)) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* We don't prompt for application secrets at all */
	if (item->type & GNOME_KEYRING_ITEM_APPLICATION_SECRET) {
		ask->response = GKR_ASK_RESPONSE_DENY;
		return GKR_ASK_STOP_REQUEST;
	}
	
#ifdef ENABLE_ACL_PROMPTS
	/* Did prompting already occur? */
	if (ask->response) {
		
		/* Mark it down if the user gave eternal access */
		if (ask->response == GKR_ASK_RESPONSE_ALLOW_FOREVER) {
			add_item_acl (item, app, 
			              GNOME_KEYRING_ACCESS_READ |
			              GNOME_KEYRING_ACCESS_WRITE |
			              GNOME_KEYRING_ACCESS_REMOVE);
			gkr_keyring_save_to_disk (item->keyring);
		}
	}
	
	/* Continue with prompting */
	return GKR_ASK_DONT_CARE;
#else /* !ENABLE_ACL_PROMPTS */
	ask->response = GKR_ASK_RESPONSE_ALLOW;
	return GKR_ASK_STOP_REQUEST;
#endif /* ENABLE_ACL_PROMPTS */
}

static gboolean
request_item_access (GkrKeyringRequest *req, GkrKeyringItem *item, 
                     GnomeKeyringAccessType access_type, gboolean secret)
{
	GnomeKeyringApplicationRef *app = req->app_ref;
	const gchar *keyring_name = NULL;
	GkrAskRequest *ask;
	gboolean is_default, ret;
	gchar *secondary;
	
	/* Simpler messages for the default keyring */
	is_default = !item->keyring || (item->keyring == gkr_keyrings_get_default ());
	
	/* An item with no keyring can happen in certain cases, let's not crash */
	if (!is_default)
		keyring_name = item->keyring->keyring_name;
	
	if (app->display_name && app->pathname) {
		if (is_default) {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' (%s) wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->display_name, app->pathname);
		} else {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' (%s) wants to access the password for '<object prop='name'/>' in %s."),
						             app->display_name, app->pathname, keyring_name);
		} 
	} else if (app->display_name) {
		if (is_default) {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->display_name);
		} else {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in %s."),
						             app->display_name, keyring_name);
		} 
	} else if (app->pathname) {
		if (is_default) {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->pathname);
		} else {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in %s."),
						             app->pathname, keyring_name);
		} 
	} else  {
		if (is_default) {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_strdup (_("An unknown application wants to access the password for '<object prop='name'/>' in the default keyring."));
		} else {
			/* TRANSLATORS: Don't translate text in markup (ie: HTML or XML tags) */
			secondary = g_markup_printf_escaped (_("An unknown application wants to access the password for '<object prop='name'/>' in %s."),
						             keyring_name);
		} 
	}

	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Allow access"), _("Allow application access to keyring?"),
	                           GKR_ASK_REQUEST_ACCESS_SOMETHING);
	
	gkr_ask_request_set_secondary (ask, secondary);
	g_free (secondary);
	
	/* Save data away for our handlers to use */
	gkr_ask_request_set_object (ask, G_OBJECT (item));
	g_object_set_data (G_OBJECT (ask), "access-secret", GUINT_TO_POINTER (secret));
	g_object_set_data (G_OBJECT (ask), "access-type", GUINT_TO_POINTER (access_type)); 
	
	g_signal_connect_data (ask, "check-request", G_CALLBACK (check_acl_ask_request), 
	                       gnome_keyring_application_ref_copy (app), 
	                       (GClosureNotify)gnome_keyring_application_ref_free, 0);
	
	gkr_ask_daemon_process (ask);
	
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	g_object_unref (ask);
	
	return ret;
}

static gboolean
request_keyring_access (GkrKeyringRequest *req, GkrKeyring *keyring)
{
	GnomeKeyringApplicationRef *app = req->app_ref;
	GkrAskRequest *ask;
	const gchar *keyring_name;
	gboolean is_default, ret;
	gchar *message, *primary;
	GkrKeyring *login;
	
	keyring_name = keyring->keyring_name;
	g_assert (keyring_name);
	
	/* Simpler messages for the default keyring */
	is_default = (keyring == gkr_keyrings_get_default ());
	
	if (app->display_name && app->pathname) {
		if (is_default) {
			/* TRANSLATORS: The default keyring is locked */
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants access to "
						           "the default keyring, but it is locked"),
						           app->display_name, app->pathname);
		} else {
			/* TRANSLATORS: The keyring '%s' is locked */
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants access to "
						           "the keyring '%s', but it is locked"),
						           app->display_name, app->pathname, keyring_name);
		}
	} else if (app->display_name) {
		if (is_default) {
			/* TRANSLATORS: The default keyring is locked */
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "default keyring, but it is locked"),
						           app->display_name);
		} else {
			/* TRANSLATORS: The keyring '%s' is locked */
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "keyring '%s', but it is locked"),
						           app->display_name, keyring_name);
		} 
	} else if (app->pathname) {
		if (is_default) {
			/* TRANSLATORS: The default keyring is locked */
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "default keyring, but it is locked"),
						           app->pathname);
		}
		else {
			/* TRANSLATORS: The keyring '%s' is locked */
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "keyring '%s', but it is locked"),
						           app->pathname, keyring_name);
		}
	} else { 
		if (is_default) {
			/* TRANSLATORS: The default keyring is locked */
			message = g_markup_printf_escaped (_("An unknown application wants access to the "
						           "default keyring, but it is locked"));
		}
		else {
			/* TRANSLATORS: The keyring '%s' is locked */
			message = g_markup_printf_escaped (_("An unknown application wants access to the "
						           "keyring '%s', but it is locked"),
						           keyring_name);
		}
	}
	
	if (is_default) {
		primary = g_strdup (_("Enter password for default keyring to unlock"));
	} else {
		primary = g_markup_printf_escaped (_("Enter password for keyring '%s' to unlock"), keyring_name);
	}

	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Unlock Keyring"), primary,
	                           GKR_ASK_REQUEST_PROMPT_PASSWORD);
	
	gkr_ask_request_set_secondary (ask, message);
	gkr_ask_request_set_object (ask, G_OBJECT (keyring));
	
	/* 
	 * If it's not the login keyring, and we have a login keyring, we can offer 
	 * to unlock automatically next time. 
	 */
	login = gkr_keyrings_get_login ();
	if (login != keyring && gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, _("Automatically unlock this keyring when I log in."));
	
	/* Intercept item access requests to see if we still need to prompt */
	g_signal_connect (ask, "check-request", G_CALLBACK (gkr_keyring_ask_check_unlock), NULL);
	
	g_free (primary);
	g_free (message);
	
	gkr_ask_daemon_process (ask);
	
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	g_object_unref (ask);
	
	return ret;
}

static gboolean
request_new_keyring_password (GkrKeyringRequest *req, const char *keyring_name, 
                              gchar **password, GQuark *volume)
{
	GnomeKeyringApplicationRef *app = req->app_ref;
	GkrAskRequest* ask;
	gboolean is_default, ret;
	gchar* message;
	
	g_assert (password);
	
	/* If we already have a password then don't prompt */
	if (*password)
		return TRUE;
	
	/* Simpler messages for the default keyring */
	is_default = !keyring_name || (strcmp (keyring_name, "default") == 0);

	if (app->display_name && app->pathname) {
		if (!is_default) {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname, keyring_name);
		} else {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname);
		} 
	} else if (app->display_name) {
		if (!is_default) {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, keyring_name);
		} else {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name);
		} 
	} else if (app->pathname) {
		if (!is_default) {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->pathname, keyring_name);
		} else {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->pathname);
		} 
	} else {
		if (!is_default) {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("An unknown application wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           keyring_name);
		} else {
			/* TRANSLATORS: The password is for the new keyring */
			message = g_markup_printf_escaped (_("An unknown application wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."));
		} 
	}

	/* And put together the ask request */
	ask = gkr_ask_request_new (_("New Keyring Password"), 
	                           _("Choose password for new keyring"), 
	                           GKR_ASK_REQUEST_NEW_PASSWORD);
	
	gkr_ask_request_set_secondary (ask, message);
	g_free (message);

	gkr_ask_request_set_location_selector (ask, TRUE);

	gkr_ask_daemon_process (ask);
	
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	if (ret) {
		g_free (*password);
		*password = egg_secure_strdup (ask->typed_password);
		*volume = ask->location_selected;
	}
	
	g_object_unref (ask);
	
	return ret;
}

static gboolean
request_change_keyring_password (GkrKeyringRequest *req, GkrKeyring* keyring, 
                                 gchar **original, gchar **password)
{
	GnomeKeyringApplicationRef *app = req->app_ref;
	GkrAskRequest *ask;
	const gchar *keyring_name;
	gboolean is_default, ret;
	gchar *message, *primary;
	guint flags;
	
	g_assert (original && password);
	
	/* Already have passwords no need to prompt */
	if (*original && *password)
		return TRUE;

	keyring_name = keyring->keyring_name;
	g_assert (keyring_name);
	
	/* Simpler messages for the default keyring */
	is_default = (keyring == gkr_keyrings_get_default ());
	
	if (app->display_name && app->pathname) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to change the password for the '%s' keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to change the password for the default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname);
		} 
	} else if (app->display_name) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants to change the password for the '%s' keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' wants to change the password for the default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name);
		} 
	} else if (app->pathname) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants to change the password for the '%s' keyring. "
						           "You have to choose the password you want to use for it."),
						           app->pathname, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' wants to change the password for the default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->pathname);
		} 
	} else {
		if (!is_default) {
			message = g_markup_printf_escaped (_("An unknown application wants to change the password for the '%s' keyring. "
						           "You have to choose the password you want to use for it."),
						           keyring_name);
		} else {
			message = g_markup_printf_escaped (_("An unknown application wants to change the password for the default keyring. "
						           "You have to choose the password you want to use for it."));
		} 
	}
	
	flags = GKR_ASK_REQUEST_CHANGE_PASSWORD;
	if (!*original)
		flags |= GKR_ASK_REQUEST_ORIGINAL_PASSWORD;

	if (is_default) {
		primary = g_markup_printf_escaped (_("Choose a new password for the '%s' keyring."), keyring_name);
	} else {
		primary = g_markup_printf_escaped (_("Choose a new password for the default keyring."));
	}
	
	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Change Keyring Password"), primary, flags);
	gkr_ask_request_set_secondary (ask, message);
	gkr_ask_request_set_object (ask, G_OBJECT (keyring));
	
	g_free (primary);
	g_free (message);
	
	gkr_ask_daemon_process (ask);
	
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	if (ret) {
		g_free (*password);
		*password = egg_secure_strdup (ask->typed_password);
		
		g_free (*original);
		*original = egg_secure_strdup (ask->original_password);
	}
	
	g_object_unref (ask);
	
	return ret;
}

static gboolean 
check_keyring_default_request (GkrAskRequest* ask)
{
	GkrKeyring *keyring;
	
	/* If another default keyring has been created in the meantime, ignore */
	if (gkr_keyrings_get_default ()) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* If a password was typed use it */
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
		g_assert (ask->typed_password);
		
		/* Create the new keyring */
		keyring = gkr_keyring_create (GKR_LOCATION_VOLUME_LOCAL, "default", 
		                              ask->typed_password);
		if (keyring == NULL) {
			g_warning ("couldn't create default keyring");
			ask->response = GKR_ASK_RESPONSE_FAILURE;
		} else {
			/* Add to our main list */
			gkr_keyrings_add (keyring);

			/* Set our newly created keyring as the default */
			gkr_keyrings_set_default (keyring);
			
			/* Let go of the initial reference to this object */
			g_object_unref (keyring);
		}
	}
	
	return GKR_ASK_DONT_CARE;
}

static GkrKeyring*
create_default_keyring (GkrKeyringRequest *req)
{
	GnomeKeyringApplicationRef *app = req->app_ref;
	GkrAskRequest* ask;
	gchar* message;
	GkrKeyring *keyring;
	
	keyring = gkr_keyrings_get_default ();
	if (keyring)
		return keyring;
	
	/* Build an appropriate message */
	if (app->display_name && app->pathname) {
		message = g_markup_printf_escaped (_("The application '%s' (%s) wants to store a password, but there is no default keyring. "
					           "To create one, you need to choose the password you wish to use for it."),
					           app->display_name, app->pathname);
	} else if (app->display_name) {
		message = g_markup_printf_escaped (_("The application '%s' wants to store a password, but there is no default keyring. "
					           "To create one, you need to choose the password you wish to use for it."),
					           app->display_name);
	} else if (app->pathname) {
		message = g_markup_printf_escaped (_("The application '%s' wants to store a password, but there is no default keyring. "
					           "To create one, you need to choose the password you wish to use for it."),
					           app->pathname);
	} else {
		message = g_markup_printf_escaped (_("An unknown application wants to store a password, but there is no default keyring. "
					           "To create one, you need to choose the password you wish to use for it."));
	}
	
	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Create Default Keyring"), _("Choose password for default keyring"), 
	                           GKR_ASK_REQUEST_NEW_PASSWORD);
	
	gkr_ask_request_set_secondary (ask, message);
	
	/* Intercept request, and actually create the keyring after prompt */
	g_signal_connect (ask, "check-request", G_CALLBACK (check_keyring_default_request), NULL);

	gkr_ask_daemon_process (ask);
	
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW)
		keyring = gkr_keyrings_get_default ();
		
	g_object_unref (ask);
	
	return keyring;
}

static GnomeKeyringResult
lookup_and_request_item_access (GkrKeyringRequest *req, gchar *keyring_name, 
                                int item_id, GnomeKeyringAccessType access_type, 
	                        gboolean access_secret, GkrKeyringItem **ret_item)
{
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	
	g_assert (ret_item);
	*ret_item = NULL;
	 
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL)
		return GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
	
	g_object_ref (keyring);
	
	item = gkr_keyring_get_item (keyring, item_id);
	if (item != NULL) {

		g_object_ref (item);

		if (request_keyring_access (req, keyring) && 
		    request_item_access (req, item, access_type, access_secret))
			*ret_item = item;
			
		g_object_unref (item);
	} 
	
	g_object_unref (keyring);
	
	return *ret_item == NULL ? GNOME_KEYRING_RESULT_DENIED : GNOME_KEYRING_RESULT_OK;
}

static GnomeKeyringResult
change_keyring_password (GkrKeyring *keyring,  const char *password)
{
	if (keyring->locked) {
		return GNOME_KEYRING_RESULT_DENIED;
	} else { 
		keyring->password = egg_secure_strdup (password);
		gkr_keyring_save_to_disk (keyring);
		return GNOME_KEYRING_RESULT_OK;
	}
}

static gboolean
op_lock_keyring (EggBuffer *packet, EggBuffer *result,
                 GkrKeyringRequest *req)
{
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyring *keyring;
	
	if (!gkr_proto_decode_op_string (packet, &opcode, &keyring_name))
		return FALSE;

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		gkr_keyring_lock (keyring);
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	}
	
	g_free (keyring_name);
	
	return TRUE;
}

static gboolean
lock_each_keyring (GkrKeyring* keyring, gpointer unused)
{
	gkr_keyring_lock (keyring);
	return TRUE;
}

static gboolean
op_lock_all (EggBuffer *packet, EggBuffer *result,
             GkrKeyringRequest *req)
{
	gkr_keyrings_foreach (lock_each_keyring, NULL);
	egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	return TRUE;
}

static gboolean
op_set_default_keyring (EggBuffer *packet, EggBuffer *result,
                        GkrKeyringRequest *req)
{
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyring *keyring;

	if (!gkr_proto_decode_op_string (packet, &opcode, &keyring_name))
		return FALSE;

	if (keyring_name == NULL) {
		gkr_keyrings_set_default (NULL);
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	} else {
		keyring = gkr_keyrings_find (keyring_name);
		if (keyring == NULL) {
			egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		} else {
			gkr_keyrings_set_default (keyring);
			egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		}
	}
	
	g_free (keyring_name);
	
	return TRUE;
}

static gboolean
op_get_default_keyring (EggBuffer *packet, EggBuffer *result,
                        GkrKeyringRequest *req)
{
	GkrKeyring* keyring;
	char *name;
	
	egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	name = NULL;
	
	keyring = gkr_keyrings_get_default ();
	if (keyring) 
		name = keyring->keyring_name;

	if (!gkr_proto_add_utf8_string (result, name))
		return FALSE;
	
	return TRUE;
}

static gboolean
add_name_to_result (GkrKeyring* keyring, gpointer result)
{
	return gkr_proto_add_utf8_string ((EggBuffer*)result, 
	                                  keyring->keyring_name);
}

static gboolean
op_list_keyrings (EggBuffer *packet, EggBuffer *result,
                  GkrKeyringRequest *req)
{
	egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	egg_buffer_add_uint32 (result, gkr_keyrings_get_count ());
	if (!gkr_keyrings_foreach (add_name_to_result, result))
		return FALSE;
	
	return TRUE;
}


static gboolean
op_set_keyring_info (EggBuffer *packet, EggBuffer *result,
                     GkrKeyringRequest *req)
{
	char    *keyring_name;
	gboolean lock_on_idle;
	guint32  lock_timeout;
	GkrKeyring *keyring;
	
	if (!gkr_proto_decode_set_keyring_info (packet,
	                                        &keyring_name,
	                                        &lock_on_idle,
	                                        &lock_timeout)) {
		return FALSE;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		
		keyring->lock_on_idle = lock_on_idle;
		keyring->lock_timeout = lock_timeout;
	}
	
	g_free (keyring_name);

	return TRUE;
}

static gboolean
op_get_keyring_info (EggBuffer *packet, EggBuffer *result,
                     GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gkr_proto_decode_op_string (packet, &opcode, &keyring_name))
		return FALSE;
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		
		egg_buffer_add_uint32 (result, keyring->lock_on_idle);
		egg_buffer_add_uint32 (result, keyring->lock_timeout);
		gkr_proto_add_time (result, keyring->mtime);
		gkr_proto_add_time (result, keyring->ctime);
		egg_buffer_add_uint32 (result, keyring->locked);
	}
	
	g_free (keyring_name);

	return TRUE;
}

static gboolean
op_create_keyring (EggBuffer *packet, EggBuffer *result,
                   GkrKeyringRequest *req)
{
	GQuark volume = GKR_LOCATION_VOLUME_LOCAL;
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gkr_proto_decode_op_string_secret (packet,
	                                        &opcode,
	                                        &keyring_name,
	                                        &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_CREATE_KEYRING);

	if (keyring_name == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_ALREADY_EXISTS);
		goto out;
	}
	
	/* Let user pick password if necessary*/
	if (!request_new_keyring_password (req, keyring_name, &password, &volume)) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	keyring = gkr_keyring_create (volume, keyring_name, password);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	/* Add to our main list */
	gkr_keyrings_add (keyring);
	
	/* Let go of the initial reference to this object */
	g_object_unref (keyring);
	g_assert (GKR_IS_KEYRING (keyring));
	
	egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
 out:
	g_free (keyring_name);
	egg_secure_strfree (password);

	return TRUE;
}

static gboolean
op_unlock_keyring (EggBuffer *packet, EggBuffer *result,
                   GkrKeyringRequest *req)
{
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_op_string_secret (packet,
	                                        &opcode,
	                                        &keyring_name,
	                                        &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_UNLOCK_KEYRING);
	
	keyring = gkr_keyrings_find (keyring_name);
	if (!keyring) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;

	} 
	
	/* User types password */
	if (password == NULL) {
		if (request_keyring_access (req, keyring)) 
			egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		else 
			egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
			
	/* Password specified */
	} else {
		if (gkr_keyring_unlock (keyring, password))
			res = GNOME_KEYRING_RESULT_OK;
		else
			res = GNOME_KEYRING_RESULT_DENIED;
		egg_buffer_add_uint32 (result, res);
	} 

 out:
	g_free (keyring_name);
	egg_secure_strfree (password);

	return TRUE;
}


static gboolean
op_delete_keyring (EggBuffer *packet, EggBuffer *result,
                   GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring = NULL;
	GnomeKeyringOpCode opcode;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_op_string (packet, &opcode, &keyring_name))
		return FALSE;
	
	g_assert (opcode == GNOME_KEYRING_OP_DELETE_KEYRING);
	
	if (keyring_name == NULL) {
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
	} else {
		keyring = gkr_keyrings_find (keyring_name);
		if (keyring == NULL) {
			res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
		} else {
			if (!gkr_keyring_remove_from_disk (keyring)) 
				res = GNOME_KEYRING_RESULT_DENIED;
			else
				res = GNOME_KEYRING_RESULT_OK;
		}
	}
	
	egg_buffer_add_uint32 (result, res);
	g_free (keyring_name);
	
	if (res == GNOME_KEYRING_RESULT_OK)
		gkr_keyrings_remove (keyring);

	return TRUE;
}

static gboolean
op_change_keyring_password (EggBuffer *packet, EggBuffer *result,
                            GkrKeyringRequest *req)
{
	char *keyring_name, *original, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gkr_proto_decode_op_string_secret_secret (packet,
	                                               &opcode,
	                                               &keyring_name,
	                                               &original,
	                                               &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD);
	
	if (keyring_name == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	/* Prompt for any missing passwords */
	if (!request_change_keyring_password (req, keyring, &original, &password)) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	gkr_keyring_lock (keyring);
	
	if (!gkr_keyring_unlock (keyring, original)) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	egg_buffer_add_uint32 (result, change_keyring_password (keyring, password));
	
 out:
	g_free (keyring_name);
	egg_secure_strfree (original);
	egg_secure_strfree (password);
	
	return TRUE;
}

static gboolean
op_list_items (EggBuffer *packet, EggBuffer *result,
               GkrKeyringRequest *req)
{
	GkrKeyring *keyring;
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyringItem *item;
	GList *l, *items;
	
	if (!gkr_proto_decode_op_string (packet, &opcode, &keyring_name))
		return FALSE;
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		egg_buffer_add_uint32 (result, 0);
		
	} else if (!request_keyring_access (req, keyring)) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		egg_buffer_add_uint32 (result, 0);
	
	} else {

		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
			
		items = NULL;
		for (l = keyring->items; l != NULL; l = l->next) {
			if (acl_check_access (l->data, req->app_ref, GNOME_KEYRING_ACCESS_LIST, FALSE))
				items = g_list_prepend (items, l->data);
		}
		items = g_list_reverse (items);

		/* Send the results */
		egg_buffer_add_uint32 (result, g_list_length (items));
		for (l = items; l != NULL; l = l->next) {
			item = l->data;
			egg_buffer_add_uint32 (result, item->id);
		}

		g_list_free (items);
	}
	
	g_free (keyring_name);
	
	return TRUE;
}

static gboolean
op_create_item (EggBuffer *packet, EggBuffer *result,
		GkrKeyringRequest *req)
{
	char *keyring_name, *display_name, *secret;
	GnomeKeyringAttributeList *attributes, *hashed;
	GkrKeyringItem *item;
	GkrKeyring *keyring;
	guint32 type;
	GnomeKeyringResult res;
	guint32 id;
	gboolean update_if_exists;

	keyring_name = display_name = secret = NULL;
	item = NULL;
	attributes = hashed = NULL;

	res = GNOME_KEYRING_RESULT_OK;
	id = 0;
	
	if (!gkr_proto_decode_create_item (packet,
	                                   &keyring_name,
	                                   &display_name,
	                                   &attributes,
	                                   &secret,
	                                   (GnomeKeyringItemType*)&type,
	                                   &update_if_exists)) {
		return FALSE;
	}

	if (display_name == NULL || secret == NULL) {
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
		goto out;
	}

	keyring = gkr_keyrings_find (keyring_name);
	
	/* Prompt user to create a new keyring if none exists */
	if (keyring == NULL && keyring_name == NULL) {
		keyring = create_default_keyring (req);
		if (keyring == NULL) {
			res = GNOME_KEYRING_RESULT_DENIED;
			goto out;
		}
	}
	
	/* Make sure we have access to the keyring */
	if (keyring != NULL) {
		if (!request_keyring_access (req, keyring)) {
			res = GNOME_KEYRING_RESULT_DENIED;
			goto out;
		}
	
	/* No such keyring found */
	} else { 
		res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
		goto out;
	}
	
	if (update_if_exists) {
		item = gkr_keyring_find_item (keyring, type, keyring->locked ? hashed : attributes, TRUE);
		if (item) {
			/* Make sure we have access to the previous item */
			if (!request_item_access (req, item, GNOME_KEYRING_ACCESS_WRITE, TRUE))
				item = NULL;
		}
	}

	if (!item) {
		item = gkr_keyring_item_create (keyring, type);
		gkr_keyring_add_item (keyring, item);
		g_object_unref (item);
	}

	/* Copy in item type flags */
	item->type |= (type & ~GNOME_KEYRING_ITEM_TYPE_MASK);

	g_free (item->display_name);
	item->display_name = g_strdup (display_name);
	egg_secure_strfree (item->secret);
	item->secret = egg_secure_strdup (secret);
	gnome_keyring_attribute_list_free (item->attributes);
	item->attributes = gnome_keyring_attribute_list_copy (attributes);
	
	add_item_acl (item, req->app_ref,
		      GNOME_KEYRING_ACCESS_READ |
		      GNOME_KEYRING_ACCESS_WRITE |
		      GNOME_KEYRING_ACCESS_REMOVE);
	
	id = item->id;
	gkr_keyring_save_to_disk (keyring);

 out:	
	g_free (keyring_name);
	g_free (display_name);
	egg_secure_strfree (secret);
	gnome_keyring_attribute_list_free (hashed);
	gnome_keyring_attribute_list_free (attributes);
	
	egg_buffer_add_uint32 (result, res);
	egg_buffer_add_uint32 (result, id);
	return TRUE;
}

static gboolean
op_delete_item (EggBuffer *packet, EggBuffer *result,
                GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_op_string_int (packet,
	                                     &opcode,
	                                     &keyring_name,
	                                     &item_id)) {
		return FALSE;
	}

	/* Request access based on what parts were desired */
	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_REMOVE, 
	                                      TRUE, 
	                                      &item);
	                                      
	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (item->keyring) {
			keyring = item->keyring;
			gkr_keyring_remove_item (keyring, item);
			gkr_keyring_save_to_disk (keyring);
		}
	}

	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_get_item_info (EggBuffer *packet, EggBuffer *result,
                  GkrKeyringRequest *req)
{
	char *keyring_name, *secret;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id, flags;
	gboolean ret = TRUE;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_get_item_info (packet, &opcode, &keyring_name,
	                                     &item_id, &flags)) {
		return FALSE;
	}

	/* Request access based on what parts were desired */
	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_READ, 
	                                      (flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET, 
	                                      &item);

	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		egg_buffer_add_uint32 (result, item->type);
		if (!gkr_proto_add_utf8_string (result, item->display_name))
			ret = FALSE;

		/* Only return the secret if it was requested */
		secret = NULL;
		if ((flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET)
			secret = item->secret;

		/* Always put the secret string or NULL in the results for compatibility */
		if (!gkr_proto_add_utf8_secret (result, secret))
			ret = FALSE;

		gkr_proto_add_time (result, item->mtime);
		gkr_proto_add_time (result, item->ctime);
	}

	g_free (keyring_name);
	return ret;
}

static gboolean
op_get_item_attributes (EggBuffer *packet, EggBuffer *result,
                        GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	gboolean ret = TRUE;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_op_string_int (packet,
	                                     &opcode,
	                                     &keyring_name,
	                                     &item_id)) {
		return FALSE;
	}

	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_READ, 
	                                      FALSE, 
	                                      &item);

	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!gkr_proto_add_attribute_list (result, item->attributes))
			ret = FALSE;
	}
	
	g_free (keyring_name);
	return ret;
}

static gboolean
op_get_item_acl (EggBuffer *packet, EggBuffer *result,
                 GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	gboolean ret = TRUE;
	GnomeKeyringResult res;

	if (!gkr_proto_decode_op_string_int (packet,
	                                     &opcode,
	                                     &keyring_name,
	                                     &item_id)) {
		return FALSE;
	}

	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_READ, 
	                                      FALSE, 
	                                      &item);

	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!gkr_proto_add_acl (result, item->acl)) 
			ret = FALSE;
	}

	g_free (keyring_name);
	return ret;
}

static gboolean
op_set_item_acl (EggBuffer *packet, EggBuffer *result,
                 GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyringItem *item;
	guint32 item_id;
	GList *acl;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_set_acl (packet,
	                               &keyring_name,
	                               &item_id,
	                               &acl)) {
		return FALSE;
	}
	
	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_WRITE, 
	                                      TRUE, 
	                                      &item);
	                                      
	if (res == GNOME_KEYRING_RESULT_OK) {
		gnome_keyring_acl_free (item->acl);
		item->acl = gnome_keyring_acl_copy (acl);
		
		if (item->keyring)
			gkr_keyring_save_to_disk (item->keyring);
	}
	
	egg_buffer_add_uint32 (result, res);

	gnome_keyring_acl_free (acl);
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_set_item_info (EggBuffer *packet, EggBuffer *result,
                  GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyringItem *item;
	guint32 item_id, type;
	char *item_name, *secret;
	GnomeKeyringResult res;
	
	if (!gkr_proto_decode_set_item_info (packet,
	                                     &keyring_name,
	                                     &item_id,
	                                     (GnomeKeyringItemType*)&type,
	                                     &item_name,
	                                     &secret)) {
		return FALSE;
	}
	
	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_WRITE, 
	                                      TRUE, 
	                                      &item);

	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		if ((type & GNOME_KEYRING_ITEM_TYPE_MASK) != GNOME_KEYRING_ITEM_NO_TYPE) {
			item->type = type;
		}
		if (item_name != NULL) {
			g_free (item->display_name);
			item->display_name = g_strdup (item_name);
		}
		if (secret != NULL) {
			egg_secure_strfree (item->secret);
			item->secret = egg_secure_strdup (secret);
		}

		if (item->keyring)
			gkr_keyring_save_to_disk (item->keyring);
	}

	g_free (keyring_name);
	g_free (item_name);
	egg_secure_strfree (secret);
	return TRUE;
}

static gboolean
op_set_daemon_display (EggBuffer *packet, EggBuffer *result,
                       GkrKeyringRequest *req)
{
	char *display;
	GnomeKeyringOpCode opcode;

	if (!gkr_proto_decode_op_string (packet, &opcode, &display))
		return FALSE;

	if (display == NULL) {
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
	} else {
		g_setenv ("DISPLAY", display, FALSE);
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	}

	g_free (display);
	return TRUE;
}

static gboolean
op_set_item_attributes (EggBuffer *packet, EggBuffer *result,
                        GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyringItem *item;
	guint32 item_id;
	GnomeKeyringResult res;
	GnomeKeyringAttributeList *attributes;

	if (!gkr_proto_decode_set_attributes (packet,
	                                      &keyring_name,
	                                      &item_id,
	                                      &attributes)) {
		return FALSE;
	}

	res = lookup_and_request_item_access (req, 
	                                      keyring_name, 
	                                      item_id, 
	                                      GNOME_KEYRING_ACCESS_WRITE, 
	                                      TRUE, 
	                                      &item);

	egg_buffer_add_uint32 (result, res);
	if (res == GNOME_KEYRING_RESULT_OK) {
		gnome_keyring_attribute_list_free (item->attributes);
		item->attributes = gnome_keyring_attribute_list_copy (attributes);

		if (item->keyring)
			gkr_keyring_save_to_disk (item->keyring);
	}

	g_free (keyring_name);	
	gnome_keyring_attribute_list_free (attributes);
	return TRUE;
}

static int
unmatched_attributes (GnomeKeyringAttributeList *attributes,
		      GnomeKeyringAttributeList *matching)
{
	int i, j;
	GnomeKeyringAttribute *matching_attribute;
	GnomeKeyringAttribute *attribute;
	gboolean found;
	int unmatching;

	unmatching = 0;
	for (i = 0; i < attributes->len; i++) {
		found = FALSE;
		attribute = &g_array_index (attributes,
					    GnomeKeyringAttribute,
					    i);
		for (j = 0; j < matching->len; j++) {
			matching_attribute = &g_array_index (matching,
							     GnomeKeyringAttribute,
							     j);
			if (strcmp (attribute->name, matching_attribute->name) == 0 &&
			    attribute->type == matching_attribute->type) {
				found = TRUE;
				break;
			}
		}
		if (!found) {
			unmatching++;
		}
	}

	return unmatching;;
}

static gint
sort_found (gconstpointer a, gconstpointer b, gpointer user_data)
{
	GnomeKeyringAttributeList *matching;
	int a_unmatched, b_unmatched;
	GkrKeyringItem *item;
	
	matching = user_data;
		
	item = GKR_KEYRING_ITEM (a);
	g_assert (GKR_IS_KEYRING_ITEM (item));
	a_unmatched = unmatched_attributes (item->attributes, matching);
	
	item = GKR_KEYRING_ITEM (b);
	g_assert (GKR_IS_KEYRING_ITEM (item));
	b_unmatched = unmatched_attributes (item->attributes, matching);

	if (a_unmatched < b_unmatched)
		return -1;
	else if (a_unmatched == b_unmatched)
		return 0;
	else
		return 1;
}

typedef struct _FindContext {
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttributeList *hashed;
	GnomeKeyringItemType type;
	GkrKeyringRequest *req;
	guint nfound;
	GList *items;
} FindContext;

static gboolean 
find_in_each_keyring (GkrKeyring* keyring, gpointer data)
{
	FindContext* ctx = (FindContext*)data;
	GkrKeyringItem *item;
	GList *ilist;
	
	g_object_ref (keyring);
	
	for (ilist = keyring->items; ilist != NULL; ilist = ilist->next) {
		item = ilist->data;
		if (!gkr_keyring_item_match (item, ctx->type, keyring->locked ? ctx->hashed : ctx->attributes, FALSE))
			continue;

		++ctx->nfound;
			
		if (keyring->locked) {
			if (!request_keyring_access (ctx->req, keyring))
				break;
		}

		if (request_item_access (ctx->req, item, GNOME_KEYRING_ACCESS_READ, TRUE)) {
			g_object_ref (item);
			ctx->items = g_list_prepend (ctx->items, item);
		}
	}

	g_object_unref (keyring);

	return TRUE;
}

static void 
unref_object (gpointer obj, gpointer data)
{
	g_object_unref (obj);
}

static gboolean
op_find (EggBuffer *packet, EggBuffer *result, GkrKeyringRequest *req)
{
	FindContext ctx;
	GList *l;
	gboolean return_val;
	
	memset (&ctx, 0, sizeof (ctx));
	
	if (!gkr_proto_decode_find (packet,
	                            &ctx.type,
	                            &ctx.attributes)) {
		return FALSE;
	}

	/* Need at least one attribute to match on */
	if (ctx.attributes->len > 0) {
		ctx.hashed = gkr_attribute_list_hash (ctx.attributes);
		ctx.nfound = 0;
		ctx.req = req;
		ctx.items = NULL;
		gkr_keyrings_foreach (find_in_each_keyring, &ctx);
	}

	/* No items given access to */
	if (ctx.nfound > 0 && ctx.items == NULL)
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		
	/* Zero items matched  */
	else if (ctx.nfound == 0)
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_NO_MATCH);

	/* More than one item found and given access to */
	else	
		egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	ctx.items = g_list_sort_with_data (ctx.items, sort_found, ctx.attributes);
	
	/* The attributes might have changed since we matched them, rematch */
	return_val = TRUE;
	for (l = ctx.items; l; l = g_list_next (l)) {
		GkrKeyringItem *item = GKR_KEYRING_ITEM (l->data);
		
		if (!item->locked && gkr_keyring_item_match (item, ctx.type, ctx.attributes, FALSE)) {
			
			/* Add it to the output */
			if (!gkr_proto_add_utf8_string (result, item->keyring->keyring_name)) {
				return_val = FALSE;
				break;
			}
	    	        
			egg_buffer_add_uint32 (result, item->id);
			
			if (!gkr_proto_add_utf8_secret (result, item->secret) ||
			    !gkr_proto_add_attribute_list (result, item->attributes)) {
				return_val = FALSE;
				break;
			}
		}
	}
	
	g_list_foreach (ctx.items, unref_object, NULL);
	g_list_free (ctx.items);

	gnome_keyring_attribute_list_free (ctx.attributes);
	gnome_keyring_attribute_list_free (ctx.hashed);
	
	return return_val;
}

static gboolean
op_prepare_daemon_environment (EggBuffer *packet, EggBuffer *result, GkrKeyringRequest *req)
{
	const gchar **daemonenv;
	gchar **environment, **e;
	gchar *x;
	gint i;

	if (!gkr_proto_decode_prepare_environment (packet, &environment))
		return FALSE;

	/* Accept environment from outside */
	for (e = environment; *e; ++e) {
		x = strchr (*e, '=');
		if (x) {
			*(x++) = 0;
			
			/* We're only interested in these environment variables */
			for (i = 0; GNOME_KEYRING_IN_ENVIRONMENT[i] != NULL; ++i) {
				if (g_str_equal (*e, GNOME_KEYRING_IN_ENVIRONMENT[i]))
				{
					g_setenv (*e, x, FALSE);
					break;
				}
			}
		}
	}
	
	g_strfreev (environment);
	
	/* 
	 * We've now definitely received everything we need to run. Ask
	 * the daemon to complete the initialization. 
	 */
	gkr_daemon_complete_initialization();

	egg_buffer_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	/* These are the environment variables that the daemon setup */
	daemonenv = gkr_daemon_util_get_environment ();
	g_return_val_if_fail (daemonenv, FALSE);
	
	egg_buffer_add_stringv (result, daemonenv);
	return TRUE;
}

GkrDaemonOperation keyring_ops[] = {
	op_lock_all, 			/* LOCK_ALL */
	op_set_default_keyring, 	/* SET_DEFAULT_KEYRING */
	op_get_default_keyring, 	/* GET_DEFAULT_KEYRING */
	op_list_keyrings, 		/* LIST_KEYRINGS */
	op_create_keyring, 		/* CREATE_KEYRING */
	op_lock_keyring, 		/* LOCK_KEYRING */
	op_unlock_keyring, 		/* UNLOCK_KEYRING */
	op_delete_keyring, 		/* DELETE_KEYRING */
	op_get_keyring_info, 		/* GET_KEYRING_INFO */
	op_set_keyring_info, 		/* SET_KEYRING_INFO */
	op_list_items, 			/* LIST_ITEMS */
	op_find, 			/* FIND */
	op_create_item, 		/* CREATE_ITEM */
	op_delete_item, 		/* DELETE_ITEM */
	op_get_item_info, 		/* GET_ITEM_INFO */
	op_set_item_info,               /* SET_ITEM_INFO */
	op_get_item_attributes,         /* GET_ITEM_ATTRIBUTES */
	op_set_item_attributes,         /* SET_ITEM_ATTRIBUTES */
	op_get_item_acl,                /* GET_ITEM_ACL */
	op_set_item_acl,                /* SET_ITEM_ACL */
	op_change_keyring_password,     /* CHANGE_KEYRING_PASSWORD */
 	op_set_daemon_display,          /* SET_DAEMON_DISPLAY */
	op_get_item_info,               /* GET_ITEM_INFO_PARTIAL */
	op_prepare_daemon_environment,	/* PREPARE_DAEMON_ENVIRONMENT */
};
