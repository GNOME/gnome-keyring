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

#include "gnome-keyring.h"
#include "gnome-keyring-daemon.h"

#include "common/gkr-buffer.h"

#include "keyrings/gkr-keyrings.h"

#include "library/gnome-keyring-memory.h"
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include "ui/gkr-ask-request.h"
#include "ui/gkr-ask-daemon.h"

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

static GnomeKeyringResult unlock_keyring (GkrKeyring *keyring, const char *password);

static guint32
hash_int (guint32 x)
{
	/* Just random 32bit hash. Security here is not very important */
	return 0x18273645 ^ x ^ (x << 16 | x >> 16);
}

static char*
md5_digest_to_ascii (unsigned char digest[16])
{
  static char hex_digits[] = "0123456789abcdef";
  char *res;
  int i;
  
  res = g_malloc (33);
  
  for (i = 0; i < 16; i++) {
    res[2*i] = hex_digits[digest[i] >> 4];
    res[2*i+1] = hex_digits[digest[i] & 0xf];
  }
  
  res[32] = 0;
  
  return res;
}

static char *
hash_string (const char *str)
{
	guchar digest[16];

	if (str == NULL)
		return NULL;

	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), NULL);
	
	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, str, strlen (str));
	return md5_digest_to_ascii (digest);
}

GnomeKeyringAttributeList *
gnome_keyring_attributes_hash (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttributeList *hashed;
	GnomeKeyringAttribute *orig_attribute;
	GnomeKeyringAttribute attribute;
	int i;

	hashed = g_array_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute));
	for (i = 0; i < attributes->len; i++) {
		orig_attribute = &gnome_keyring_attribute_list_index (attributes, i);
		attribute.name = g_strdup (orig_attribute->name);
		attribute.type = orig_attribute->type;
		switch (attribute.type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			attribute.value.string = hash_string (orig_attribute->value.string);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			attribute.value.integer = hash_int (orig_attribute->value.integer);
			break;
		default:
			g_assert_not_reached ();
		}
		g_array_append_val (hashed, attribute);
	}

	return hashed;
}

GnomeKeyringApplicationRef *
gnome_keyring_application_ref_new_from_pid (pid_t pid)
{
	GnomeKeyringApplicationRef *app_ref;

	app_ref = g_new0 (GnomeKeyringApplicationRef, 1);

#if defined(__linux__) || defined(__FreeBSD__)
	g_assert (pid > 0);
	{
		char *buffer;
		int len;
		char *path = NULL;
		
#if defined(__linux__)
		path = g_strdup_printf ("/proc/%d/exe", (gint)pid);
#elif defined(__FreeBSD__)
		path = g_strdup_printf ("/proc/%d/file", (gint)pid);
#endif
		buffer = g_file_read_link (path, NULL);
		g_free (path);

		len = (buffer != NULL) ? strlen (buffer) : 0;
		if (len > 0) {
			app_ref->pathname = g_malloc (len + 1);
			memcpy (app_ref->pathname, buffer, len);
			app_ref->pathname[len] = 0;
		}
		g_free (buffer);
	}
#endif

	return app_ref;
}

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

static gboolean
match_attributes (GkrKeyringItem *item,
		  GnomeKeyringAttributeList *attributes,
		  gboolean match_all)
{
	int i, j;
	GnomeKeyringAttribute *item_attribute;
	GnomeKeyringAttribute *attribute;
	gboolean found;
	int attributes_matching;

	attributes_matching = 0;
	for (i = 0; i < attributes->len; i++) {
		found = FALSE;
		attribute = &g_array_index (attributes,
					    GnomeKeyringAttribute,
					    i);
		for (j = 0; j < item->attributes->len; j++) {
			item_attribute = &g_array_index (item->attributes,
							 GnomeKeyringAttribute,
							 j);
			if (strcmp (attribute->name, item_attribute->name) == 0) {
				found = TRUE;
				attributes_matching++;
				if (attribute->type != item_attribute->type) {
					return FALSE;
				}
				switch (attribute->type) {
				case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
					if ((attribute->value.string == NULL || item_attribute->value.string == NULL) && 
					    attribute->value.string != item_attribute->value.string) {
						return FALSE;
					}
					if (strcmp (attribute->value.string, item_attribute->value.string) != 0) {
						return FALSE;
					}
					break;
				case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
					if (attribute->value.integer != item_attribute->value.integer) {
						return FALSE;
					}
					break;
				default:
					g_assert_not_reached ();
				}
			}
		}
		if (!found) {
			return FALSE;
		}
	}
	if (match_all) {
		return attributes_matching == attributes->len;
	}
	return TRUE;
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
}

static GkrAskRequest*
access_request_from_item (GnomeKeyringApplicationRef *app, GkrKeyringItem *item, 
                          GnomeKeyringAccessType access_type, gboolean secret)
{
	const gchar *keyring_name = NULL;
	GkrAskRequest *ask;
	gboolean is_default;
	gchar *secondary;
	
	/* Simpler messages for the default keyring */
	is_default = !item->keyring || (item->keyring == gkr_keyrings_get_default ());
	
	/* An item with no keyring can happen in certain cases, let's not crash */
	if (!is_default)
		keyring_name = item->keyring->keyring_name;
	
	if (app->display_name && app->pathname) {
		if (is_default) {
			secondary = g_markup_printf_escaped (_("The application '%s' (%s) wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->display_name, app->pathname);
		} else {
			secondary = g_markup_printf_escaped (_("The application '%s' (%s) wants to access the password for '<object prop='name'/>' in %s."),
						             app->display_name, app->pathname, keyring_name);
		} 
	} else if (app->display_name) {
		if (is_default) {
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->display_name);
		} else {
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in %s."),
						             app->display_name, keyring_name);
		} 
	} else if (app->pathname) {
		if (is_default) {
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in the default keyring."),
						             app->pathname);
		} else {
			secondary = g_markup_printf_escaped (_("The application '%s' wants to access the password for '<object prop='name'/>' in %s."),
						             app->pathname, keyring_name);
		} 
	} else  {
		if (is_default) {
			secondary = g_strdup (_("An unknown application wants to access the password for '<object prop='name'/>' in the default keyring."));
		} else {
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
	
	return ask;
}

static gboolean 
check_keyring_ask_request (GkrAskRequest* ask)
{
	GkrKeyring *keyring;
	
	keyring = GKR_KEYRING (gkr_ask_request_get_object (ask));
	g_assert (GKR_IS_KEYRING (keyring));
	
	/* If the keyring is unlocked then no need to continue */
	if (!keyring->locked) {
		ask->response = GKR_ASK_RESPONSE_ALLOW;
		return GKR_ASK_STOP_REQUEST;
	}
	
	/* If they typed a password, try it out */
	if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
		
		g_assert (ask->typed_password);
		unlock_keyring (keyring, ask->typed_password);
		if (keyring->locked) {
			/* Not happy, try again */
			ask->response = GKR_ASK_RESPONSE_NONE;
			return GKR_ASK_CONTINUE_REQUEST;
		}
	}
	
	return GKR_ASK_DONT_CARE;
}

static GkrAskRequest*
access_request_from_keyring (GnomeKeyringApplicationRef *app, GkrKeyring *keyring, 
                             GnomeKeyringAccessType access_type)
{
	GkrAskRequest *ask;
	const gchar *keyring_name;
	gboolean is_default;
	gchar *message, *primary;
	
	keyring_name = keyring->keyring_name;
	g_assert (keyring_name);
	
	/* Simpler messages for the default keyring */
	is_default = (keyring == gkr_keyrings_get_default ());
	
	if (app->display_name && app->pathname) {
		if (is_default) {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants access to "
						           "the default keyring, but it is locked"),
						           app->display_name, app->pathname);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants access to "
						           "the keyring '%s', but it is locked"),
						           app->display_name, app->pathname, keyring_name);
		}
	} else if (app->display_name) {
		if (is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "default keyring, but it is locked"),
						           app->display_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "keyring '%s', but it is locked"),
						           app->display_name, keyring_name);
		} 
	} else if (app->pathname) {
		if (is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "default keyring, but it is locked"),
						           app->pathname);
		}
		else {
			message = g_markup_printf_escaped (_("The application '%s' wants access to the "
						           "keyring '%s', but it is locked"),
						           app->pathname, keyring_name);
		}
	} else { 
		if (is_default) {
			message = g_markup_printf_escaped (_("An unknown application wants access to the "
						           "default keyring, but it is locked"));
		}
		else {
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
	
	/* Intercept item access requests to see if we still need to prompt */
	g_signal_connect (ask, "check-request", G_CALLBACK (check_keyring_ask_request), NULL);
	
	g_free (primary);
	g_free (message);
	
	return ask;
}

static GkrAskRequest*
access_request_for_new_keyring_password (GnomeKeyringApplicationRef *app, 
                                         const char *keyring_name)
{
	GkrAskRequest* ask;
	gboolean is_default;
	gchar* message;
	
	/* Simpler messages for the default keyring */
	is_default = !keyring_name || (strcmp (keyring_name, "default") == 0);

	if (app->display_name && app->pathname) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' (%s) wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, app->pathname);
		} 
	} else if (app->display_name) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->display_name, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->display_name);
		} 
	} else if (app->pathname) {
		if (!is_default) {
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           app->pathname, keyring_name);
		} else {
			message = g_markup_printf_escaped (_("The application '%s' wants to create a new default keyring. "
						           "You have to choose the password you want to use for it."),
						           app->pathname);
		} 
	} else {
		if (!is_default) {
			message = g_markup_printf_escaped (_("An unknown application wants to create a new keyring called '%s'. "
						           "You have to choose the password you want to use for it."),
						           keyring_name);
		} else {
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
	return ask;
}

static GkrAskRequest*
access_request_for_change_keyring_password (GnomeKeyringApplicationRef *app,
                                            GkrKeyring* keyring, gboolean need_original)
{
	GkrAskRequest *ask;
	const gchar *keyring_name;
	gboolean is_default;
	gchar *message, *primary;
	guint flags;
	
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
	
	flags = GKR_ASK_REQUEST_NEW_PASSWORD;
	if (need_original)
		flags |= GKR_ASK_REQUEST_ORIGINAL_PASSWORD;

	if (is_default) {
		primary = g_markup_printf_escaped (_("Choose a new password for the '%s' keyring. "), keyring_name);
	} else {
		primary = g_markup_printf_escaped (_("Choose a new password for the default keyring. "));
	}
	
	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Change Keyring Password"), primary, flags);
	gkr_ask_request_set_secondary (ask, message);
	gkr_ask_request_set_object (ask, G_OBJECT (keyring));
	
	g_free (primary);
	g_free (message);
	
	return ask;
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
		keyring = gkr_keyring_create ("default", ask->typed_password);
		if (keyring == NULL) {
			g_warning ("couldn't create default keyring");
			ask->response = GKR_ASK_RESPONSE_FAILURE;
		} else {
			/* Set our newly created keyring as the default */
			gkr_keyrings_set_default (keyring);
		}
	}
	
	return GKR_ASK_DONT_CARE;
}

static GkrAskRequest*
access_request_default_keyring (GnomeKeyringApplicationRef *app)
{
	GkrAskRequest* ask;
	gchar* message;
	
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

	return ask;
}

static GnomeKeyringResult
change_keyring_password (GkrKeyring *keyring,  const char *password)
{
	if (keyring->locked) {
		return GNOME_KEYRING_RESULT_DENIED;
	} else { 
		keyring->password = gnome_keyring_memory_strdup (password);
		gkr_keyring_save_to_disk (keyring);
		return GNOME_KEYRING_RESULT_OK;
	}
}

static GnomeKeyringResult
unlock_keyring (GkrKeyring *keyring, const char *password)
{
	if (!keyring->locked)
		return GNOME_KEYRING_RESULT_OK;
		
	g_assert (keyring->password == NULL);
		
	keyring->password = gnome_keyring_memory_strdup (password);
	if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
		gnome_keyring_free_password (keyring->password);
		keyring->password = NULL;
	}
	if (keyring->locked) {
		g_assert (keyring->password == NULL);
		return GNOME_KEYRING_RESULT_DENIED;
	} else {
		g_assert (keyring->password != NULL);
		return GNOME_KEYRING_RESULT_OK;
	}
}

static void
lock_keyring (GkrKeyring *keyring)
{
	if (keyring->locked) {
		return;
	}
	if (keyring->file == NULL) {
		/* Never lock the session keyring */
		return;
	}
	g_assert (keyring->password != NULL);
	
	gnome_keyring_free_password (keyring->password);
	keyring->password = NULL;
	if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
		/* Failed to re-read, remove the keyring */
		g_warning ("Couldn't re-read keyring %s\n", keyring->keyring_name);
		gkr_keyrings_remove (keyring);
	}
}

static gboolean
op_lock_keyring_execute (GkrBuffer *packet,
			 GkrBuffer *result,
			 GkrKeyringRequest *req)
{
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		lock_keyring (keyring);
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	}
	
	return TRUE;
}

static gboolean
lock_each_keyring (GkrKeyring* keyring, gpointer unused)
{
	lock_keyring (keyring);
	return TRUE;
}

static gboolean
op_lock_all_execute (GkrBuffer *packet,
		     GkrBuffer *result,
		     GkrKeyringRequest *req)
{
	gkr_keyrings_foreach (lock_each_keyring, NULL);
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	return TRUE;
}

static gboolean
op_set_default_keyring_execute (GkrBuffer *packet,
				GkrBuffer *result,
				GkrKeyringRequest *req)
{
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyring *keyring;

	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gkr_keyrings_set_default (NULL);
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	} else {
		keyring = gkr_keyrings_find (keyring_name);
		if (keyring == NULL) {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		} else {
			gkr_keyrings_set_default (keyring);
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		}
	}
	
	g_free (keyring_name);
	
	return TRUE;
}

static gboolean
op_get_default_keyring_execute (GkrBuffer *packet,
				GkrBuffer *result,
				GkrKeyringRequest *req)
{
	GkrKeyring* keyring;
	char *name;
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	name = NULL;
	
	keyring = gkr_keyrings_get_default ();
	if (keyring) 
		name = keyring->keyring_name;

	if (!gnome_keyring_proto_add_utf8_string (result, name)) {
		return FALSE;
	}
	
	return TRUE;
}

static gboolean
add_name_to_result (GkrKeyring* keyring, gpointer result)
{
	return gnome_keyring_proto_add_utf8_string ((GkrBuffer*)result, 
	                                            keyring->keyring_name);
}

static gboolean
op_list_keyrings_execute (GkrBuffer *packet,
			  GkrBuffer *result,
			  GkrKeyringRequest *req)
{
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	gnome_keyring_proto_add_uint32 (result, gkr_keyrings_get_count ());
	if (!gkr_keyrings_foreach (add_name_to_result, result))
		return FALSE;
	
	return TRUE;
}


static gboolean
op_set_keyring_info_execute (GkrBuffer *packet,
			     GkrBuffer *result,
			     GkrKeyringRequest *req)
{
	char    *keyring_name;
	gboolean lock_on_idle;
	guint32  lock_timeout;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_set_keyring_info (packet,
							  &keyring_name,
							  &lock_on_idle,
							  &lock_timeout)) {
		return FALSE;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		
		keyring->lock_on_idle = lock_on_idle;
		keyring->lock_timeout = lock_timeout;
	}
	
	g_free (keyring_name);

	return TRUE;
}

static gboolean
op_get_keyring_info_execute (GkrBuffer *packet,
			     GkrBuffer *result,
			     GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		
		gnome_keyring_proto_add_uint32 (result, keyring->lock_on_idle);
		gnome_keyring_proto_add_uint32 (result, keyring->lock_timeout);
		gnome_keyring_proto_add_time (result, keyring->mtime);
		gnome_keyring_proto_add_time (result, keyring->ctime);
		gnome_keyring_proto_add_uint32 (result, keyring->locked);
	}
	
	g_free (keyring_name);

	return TRUE;
}

static gboolean
op_create_keyring_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	GnomeKeyringOpCode opcode;
	char *keyring_name, *password;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string_secret (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		/* param error */
		goto out;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		/* already exist */
		goto out;
	}
	
	if (password == NULL) {
		/* Let user pick password */
		req->ask_requests = g_list_prepend (req->ask_requests,
					access_request_for_new_keyring_password (req->app_ref, keyring_name));
	}

 out:
	g_free (keyring_name);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static gboolean
op_create_keyring_execute (GkrBuffer *packet,
			   GkrBuffer *result,
			   GkrKeyringRequest *req)
{
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_secret (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_CREATE_KEYRING);

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_ALREADY_EXISTS);
		goto out;
	}
	
	if (password == NULL) {
		if (req->ask_requests != NULL) {
			ask = req->ask_requests->data;
			password = gnome_keyring_memory_strdup (ask->typed_password);
		}
	}
	
	if (password == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	keyring = gkr_keyring_create (keyring_name, password);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	/* Add to our main list */
	gkr_keyrings_add (keyring);
	
	/* Let go of the initial reference to this object */
	g_object_unref (keyring);
	g_assert (GKR_IS_KEYRING (keyring));
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
 out:
	g_free (keyring_name);
	gnome_keyring_free_password (password);

	return TRUE;
}

static gboolean
op_unlock_keyring_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	GnomeKeyringOpCode opcode;
	char *keyring_name, *password;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string_secret (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL)
		goto out;

	if (keyring->locked && password == NULL) {
		/* Let user type password */
		req->ask_requests = g_list_prepend (req->ask_requests,
					access_request_from_keyring (req->app_ref, keyring, 
		                                                     GNOME_KEYRING_ACCESS_READ));
	}

 out:
	g_free (keyring_name);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static gboolean
op_unlock_keyring_execute (GkrBuffer *packet,
			   GkrBuffer *result,
			   GkrKeyringRequest *req)
{
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_secret (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_UNLOCK_KEYRING);
	
	keyring = gkr_keyrings_find (keyring_name);

	if (!keyring) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;

	} 

	/* If the keyring is unlocked, as done by the ask request, then good to go */
	if (!keyring->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		goto out;
	} 
	
	/* See if a password prompt got put up */
	if (password == NULL && req->ask_requests != NULL) {
		ask = req->ask_requests->data;
		password = gnome_keyring_memory_strdup (ask->typed_password);
	}

	if (password == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, unlock_keyring (keyring, password));
	
 out:
	g_free (keyring_name);
	gnome_keyring_free_password (password);

	return TRUE;
}


static gboolean
op_delete_keyring_execute (GkrBuffer *packet,
			   GkrBuffer *result,
			   GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GnomeKeyringResult res;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_DELETE_KEYRING);
	
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
	} else {
		if (!gkr_keyring_remove_from_disk (keyring)) 
			res = GNOME_KEYRING_RESULT_DENIED;
		else
			res = GNOME_KEYRING_RESULT_OK;
	}
	
	gnome_keyring_proto_add_uint32 (result, res);
	g_free (keyring_name);
	
	if (res == GNOME_KEYRING_RESULT_OK)
		gkr_keyrings_remove (keyring);

	return TRUE;
}

static gboolean
op_change_keyring_password_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	GnomeKeyringOpCode opcode;
	char *keyring_name, *original, *password;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string_secret_secret (packet,
							  &opcode,
							  &keyring_name,
							  &original,
							  &password)) {
		return FALSE;
	}

	keyring = NULL;
	
	if (keyring_name != NULL)
		keyring = gkr_keyrings_find (keyring_name);

	/* Must specify a valid keyring */
	if (keyring != NULL && password == NULL) {
		if (original == NULL ) {
			/* Prompt for original and Let user pick password */
			req->ask_requests = g_list_prepend (req->ask_requests,
					access_request_for_change_keyring_password (req->app_ref, keyring, TRUE));
		} else {
			/* Use original given to us Let user pick password */
			req->ask_requests = g_list_prepend (req->ask_requests,
					access_request_for_change_keyring_password (req->app_ref, keyring, FALSE));
		}
	}

	g_free (keyring_name);
	gnome_keyring_free_password (original);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static gboolean
op_change_keyring_password_execute (GkrBuffer *packet,
			   GkrBuffer *result,
			   GkrKeyringRequest *req)
{
	char *keyring_name, *original, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_secret_secret (packet,
							  &opcode,
							  &keyring_name,
							  &original,
							  &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD);
	
	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
	
	keyring = gkr_keyrings_find (keyring_name);
	
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	if (original == NULL) {
		if (req->ask_requests != NULL) {
			ask = req->ask_requests->data;
			original = gnome_keyring_memory_strdup (ask->original_password);
		}
	}

	if (original ==NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	lock_keyring(keyring);
	
	if ( unlock_keyring(keyring, original) != GNOME_KEYRING_RESULT_OK ) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	if (password == NULL) {
		if (req->ask_requests != NULL) {
			ask = req->ask_requests->data;
			password = gnome_keyring_memory_strdup (ask->typed_password);
		}
	}
	
	if (password == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	gnome_keyring_proto_add_uint32 (result, change_keyring_password (keyring, password));
	
 out:
	g_free (keyring_name);
	gnome_keyring_free_password (original);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static gboolean
op_list_items_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		req->ask_requests =
			g_list_prepend (req->ask_requests,
					access_request_from_keyring (req->app_ref, keyring, GNOME_KEYRING_ACCESS_READ));
	}
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_list_items_execute (GkrBuffer *packet,
		       GkrBuffer *result,
		       GkrKeyringRequest *req)
{
	GkrKeyring *keyring;
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyringItem *item;
	GList *l, *items;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	/* Keyring name can be null for default keyring */
	if (gkr_keyrings_find (keyring_name) == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		gnome_keyring_proto_add_uint32 (result, 0);
	} else if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		gnome_keyring_proto_add_uint32 (result, 0);
	} else {
		ask = req->ask_requests->data;
		keyring = GKR_KEYRING (gkr_ask_request_get_object (ask));
		g_assert (GKR_IS_KEYRING (keyring));

		if (keyring->locked) {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
			gnome_keyring_proto_add_uint32 (result, 0);
		} else {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
			
			items = NULL;
			for (l = keyring->items; l != NULL; l = l->next) {
				if (acl_check_access (l->data, req->app_ref, GNOME_KEYRING_ACCESS_LIST, FALSE))
					items = g_list_prepend (items, l->data);
			}
			items = g_list_reverse (items);

			/* Send the results */
			gnome_keyring_proto_add_uint32 (result, g_list_length (items));
			for (l = items; l != NULL; l = l->next) {
				item = l->data;
				gnome_keyring_proto_add_uint32 (result, item->id);
			}

			g_list_free (items);
		}
	}
	
	return TRUE;
}

static gboolean
op_create_item_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringAttributeList *attributes;
	guint32 type;
	gboolean update_if_exists;
	GnomeKeyringAttributeList *hashed;
	GList *ilist;
	gboolean found_existing;
	GkrKeyringItem *item;
	GkrAskRequest *access_request;
	
	if (!gnome_keyring_proto_decode_create_item (packet,
						     &keyring_name, NULL,
						     &attributes, NULL,
						     (GnomeKeyringItemType *) &type,
						     &update_if_exists)) {
		return FALSE;
	}

	found_existing = FALSE;

	if (keyring_name == NULL) {
		keyring = gkr_keyrings_get_default ();
		
		if (keyring == NULL) {
			req->ask_requests =
				g_list_prepend (req->ask_requests,
						access_request_default_keyring (req->app_ref));
		}
	} else {
		keyring = gkr_keyrings_find (keyring_name);
	}
	
	if (update_if_exists && keyring != NULL) {
		hashed = gnome_keyring_attributes_hash (attributes);

		for (ilist = keyring->items; ilist != NULL; ilist = ilist->next) {
			item = ilist->data;
			if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) == (type & GNOME_KEYRING_ITEM_TYPE_MASK) &&
			    match_attributes (item, keyring->locked ? hashed : attributes, TRUE)) {
				found_existing = TRUE;
				access_request =
					access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_WRITE, TRUE);
				req->ask_requests = g_list_prepend (req->ask_requests, access_request);
				break;
			}
		}
		
		gnome_keyring_attribute_list_free (hashed);
	}
	gnome_keyring_attribute_list_free (attributes);

	if (!found_existing && keyring != NULL) {
		req->ask_requests =
			g_list_prepend (req->ask_requests,
					access_request_from_keyring (req->app_ref, keyring, GNOME_KEYRING_ACCESS_WRITE));
	}
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_create_item_execute (GkrBuffer *packet,
			GkrBuffer *result,
			GkrKeyringRequest *req)
{
	char *keyring_name, *display_name, *secret;
	GnomeKeyringAttributeList *attributes;
	GkrKeyringItem *item;
	GkrKeyring *keyring;
	guint32 type;
	GnomeKeyringResult res;
	guint32 id;
	gboolean update_if_exists;
	GkrAskRequest *ask;
	GObject *obj;

	keyring_name = display_name = secret = NULL;
	attributes = NULL;

	res = GNOME_KEYRING_RESULT_OK;
	id = 0;
	
	if (!gnome_keyring_proto_decode_create_item (packet,
						     &keyring_name,
						     &display_name,
						     &attributes,
						     &secret,
						     (GnomeKeyringItemType *) &type,
						     &update_if_exists)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		if (keyring_name == NULL) {
			res = GNOME_KEYRING_RESULT_DENIED;
		} else {
			res = GNOME_KEYRING_RESULT_NO_SUCH_KEYRING;
		}
		goto bail;
	}
	
	if (keyring->locked) {
		res = GNOME_KEYRING_RESULT_DENIED;
		goto bail;
	}

	if ((type & GNOME_KEYRING_ITEM_TYPE_MASK) >= GNOME_KEYRING_ITEM_LAST_TYPE ||
	    display_name == NULL ||
	    secret == NULL) {
		res = GNOME_KEYRING_RESULT_BAD_ARGUMENTS;
		goto bail;
	}

	if (req->ask_requests == NULL) {
		res = GNOME_KEYRING_RESULT_DENIED;
		goto bail;
	}
	item = NULL;
	ask = req->ask_requests->data;
	
	/* We can have different kinds of access requests, so find item */
	obj = gkr_ask_request_get_object (ask);
	if (GKR_IS_KEYRING_ITEM (obj))
		item = GKR_KEYRING_ITEM (obj);

	if (item == NULL) {
		item = gkr_keyring_item_create (keyring, type);
		gkr_keyring_add_item (keyring, item);
	}

	if (item == NULL) {
		res = GNOME_KEYRING_RESULT_DENIED;
		goto bail;
	}

	/* Copy in item type flags */
	item->type |= (type & ~GNOME_KEYRING_ITEM_TYPE_MASK);

	g_free (item->display_name);
	item->display_name = g_strdup (display_name);
	gnome_keyring_free_password (item->secret);
	item->secret = gnome_keyring_memory_strdup (secret);
	if (item->attributes != NULL) {
		gnome_keyring_attribute_list_free (item->attributes);
	}
	item->attributes = gnome_keyring_attribute_list_copy (attributes);
	add_item_acl (item, req->app_ref,
		      GNOME_KEYRING_ACCESS_READ |
		      GNOME_KEYRING_ACCESS_WRITE |
		      GNOME_KEYRING_ACCESS_REMOVE);
	
	id = item->id;
	
	gkr_keyring_save_to_disk (keyring);

 bail:	
	g_free (keyring_name);
	g_free (display_name);
	gnome_keyring_free_password (secret);
	gnome_keyring_attribute_list_free (attributes);
	
	gnome_keyring_proto_add_uint32 (result, res);
	gnome_keyring_proto_add_uint32 (result, id);
	return TRUE;
}


static gboolean
op_delete_item_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		item = gkr_keyring_find_item (keyring, item_id);
		if (item != NULL) {
			ask = access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_REMOVE, TRUE);
			req->ask_requests = g_list_prepend (req->ask_requests, ask);
		}
	}

	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_delete_item_execute (GkrBuffer *packet,
			GkrBuffer *result,
			GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	/* Will return default keyring for null */		
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));
	
	if (item == NULL || item->keyring != keyring || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gkr_keyring_remove_item (keyring, item);
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gkr_keyring_save_to_disk (keyring);

 out:
	
	g_free (keyring_name);
	return TRUE;
}



static gboolean
op_get_item_info_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id, flags;
	GkrAskRequest *ask;

	if (!gnome_keyring_proto_decode_get_item_info (packet, &opcode, &keyring_name, 
						       &item_id, &flags)) {
		return FALSE;
	}

	/* NULL will return default keyring */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		item = gkr_keyring_find_item (keyring, item_id);
		if (item != NULL) {
			/* Request access based on what parts were desired */
			if ((flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET) {
				ask = access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_READ, TRUE);
			} else {
				ask = access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_READ, FALSE);
			}
			req->ask_requests = g_list_prepend (req->ask_requests, ask);
		}
	}

	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_get_item_info_execute (GkrBuffer *packet,
			  GkrBuffer *result,
			  GkrKeyringRequest *req)
{
	char *keyring_name, *secret;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id, flags;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_get_item_info (packet, &opcode, &keyring_name,
						       &item_id, &flags)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gnome_keyring_proto_add_uint32 (result, item->type);
	if (!gnome_keyring_proto_add_utf8_string (result, item->display_name)) {
		return FALSE;
	}

	/* Only return the secret if it was requested */
	secret = NULL;
	if ((flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET)
		secret = item->secret;

	/* Always put the secret string or NULL in the results for compatibility */
	if (!gnome_keyring_proto_add_utf8_secret (result, secret)) {
		return FALSE;
	}

	gnome_keyring_proto_add_time (result, keyring->mtime);
	gnome_keyring_proto_add_time (result, keyring->ctime);
	
out:
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_get_item_acl_or_attributes_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		item = gkr_keyring_find_item (keyring, item_id);
		if (item != NULL) {
			ask = access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_READ, FALSE);
			req->ask_requests = g_list_prepend (req->ask_requests, ask);
		}
	}

	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_get_item_attributes_execute (GkrBuffer *packet,
				GkrBuffer *result,
				GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	if (!gnome_keyring_proto_add_attribute_list (result, item->attributes)) {
		g_free (keyring_name);
		return FALSE;
	}

out:
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_get_item_acl_execute (GkrBuffer *packet,
			 GkrBuffer *result,
			 GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	if (!gnome_keyring_proto_add_acl (result, item->acl)) {
		g_free (keyring_name);
		return FALSE;
	}

out:
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_set_item_acl_execute (GkrBuffer *packet,
			 GkrBuffer *result,
			 GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id;
	GkrAskRequest *ask;
	GList *acl;
	
	if (!gnome_keyring_proto_decode_set_acl (packet,
						 &keyring_name,
						 &item_id,
						 &acl)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gnome_keyring_acl_free (item->acl);
	item->acl = gnome_keyring_acl_copy (acl);

out:
	gnome_keyring_acl_free (acl);
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_set_item_info_or_attributes_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GkrAskRequest *ask;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	keyring = gkr_keyrings_find (keyring_name);
	if (keyring != NULL) {
		item = gkr_keyring_find_item (keyring, item_id);
		if (item != NULL) {
			ask = access_request_from_item (req->app_ref, item, GNOME_KEYRING_ACCESS_WRITE, TRUE);
			req->ask_requests = g_list_prepend (req->ask_requests, ask);
		}
	}

	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_set_item_info_execute (GkrBuffer *packet,
			  GkrBuffer *result,
			  GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id, type;
	GkrAskRequest *ask;
	char *item_name, *secret;
	
	if (!gnome_keyring_proto_decode_set_item_info (packet,
						       &keyring_name,
						       &item_id,
						       (GnomeKeyringItemType *) &type,
						       &item_name,
						       &secret)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->keyring != keyring || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	if ((type & GNOME_KEYRING_ITEM_TYPE_MASK) != GNOME_KEYRING_ITEM_NO_TYPE) {
		item->type = type;
	}
	if (item_name != NULL) {
		g_free (item->display_name);
		item->display_name = g_strdup (item_name);
	}
	if (secret != NULL) {
		gnome_keyring_free_password (item->secret);
		item->secret = gnome_keyring_memory_strdup (secret);
	}
	
out:
	
	g_free (keyring_name);
	g_free (item_name);
	gnome_keyring_free_password (secret);
	return TRUE;
}

static gboolean
op_set_daemon_display_execute (GkrBuffer *packet,
			       GkrBuffer *result,
			       GkrKeyringRequest *req)
{
       char *display;
       GnomeKeyringOpCode opcode;

       if (!gnome_keyring_proto_decode_op_string (packet,
						  &opcode,
						  &display)) {
               return FALSE;
       }

       if ( display == NULL ) {
               gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
               goto out;
       }

       if (gkr_ask_daemon_get_display () == NULL && (g_strrstr (display, ":") != NULL)) {
               gkr_ask_daemon_set_display (display);
       } else {
               gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
               goto out;
       }

       gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

out:
    g_free (display);
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

static gboolean
op_set_item_attributes_execute (GkrBuffer *packet,
				GkrBuffer *result,
				GkrKeyringRequest *req)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id;
	GkrAskRequest *ask;
	GnomeKeyringAttributeList *attributes;
	
	if (!gnome_keyring_proto_decode_set_attributes (packet,
							&keyring_name,
							&item_id,
							&attributes)) {
		return FALSE;
	}

	/* Will return default keyring for NULL */
	keyring = gkr_keyrings_find (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (req->ask_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	ask = req->ask_requests->data;
	item = GKR_KEYRING_ITEM (gkr_ask_request_get_object (ask));

	if (item == NULL || item->keyring != keyring || item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	item->attributes = gnome_keyring_attribute_list_copy (attributes);
	
out:
	
	gnome_keyring_attribute_list_free (attributes);
	g_free (keyring_name);
	return TRUE;
}

static gint
sort_found (gconstpointer  a,
	    gconstpointer  b,
	    gpointer       user_data)
{
	GnomeKeyringAttributeList *matching;
	int a_unmatched, b_unmatched;
	GkrKeyringItem *item;
	GObject *a_obj, *b_obj;
	GType a_type, b_type;
	
	matching = user_data;

	a_obj = gkr_ask_request_get_object (GKR_ASK_REQUEST (a));
	b_obj = gkr_ask_request_get_object (GKR_ASK_REQUEST (b));
	
	g_assert (a_obj && b_obj);
	
	a_type = G_OBJECT_TYPE (a_obj);
	b_type = G_OBJECT_TYPE (b_obj);
	
	if (a_type < b_type)
		return -1;
	else if (a_type > b_type)
		return 1;
		
	/* If it's not an item, we don't care */
	else if (!GKR_IS_KEYRING_ITEM (a_obj))
		return 0;
		
	item = GKR_KEYRING_ITEM (a_obj);
	a_unmatched = unmatched_attributes (item->attributes, matching);
	
	item = GKR_KEYRING_ITEM (b_obj);
	b_unmatched = unmatched_attributes (item->attributes, matching);

	if (a_unmatched < b_unmatched) {
		return -1;
	} else if (a_unmatched == b_unmatched) {
		return 0;
	} else {
		return 1;
	}
}


static gboolean
op_find_execute (GkrBuffer *packet,
		 GkrBuffer *result,
		 GkrKeyringRequest *req)
{
	GList *l;
	GnomeKeyringAttributeList *attributes;
	GkrAskRequest *ask;
	gboolean return_val;
	GkrKeyringItem *item;
	GnomeKeyringItemType type;
	GObject *obj;
	
	/* No items matched? */
	if (GPOINTER_TO_UINT (req->data) == 0)
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	 
	/* No items given access to */
	else if (req->ask_requests == NULL)
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		
	/* Items matched and given access to */
	else
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	
	if (!gnome_keyring_proto_decode_find (packet,
					      &type,
					      &attributes)) {
		return FALSE;
	}
	
	req->ask_requests = g_list_sort_with_data (req->ask_requests,
	                                              sort_found, attributes);
	
	/* The attributes might have changed since we matched them, rematch */
	return_val = TRUE;
	for (l = req->ask_requests; l != NULL; l = l->next) {
		ask = l->data;
		
		obj = gkr_ask_request_get_object (ask);
		g_assert (obj);
		
		/* We also have keyring unlock requests mixed in here, so ignore those */
		if (!GKR_IS_KEYRING_ITEM (obj))
			continue;
			
		item = GKR_KEYRING_ITEM (obj); 
		if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) == (type & GNOME_KEYRING_ITEM_TYPE_MASK) &&
		    !item->locked &&
		    match_attributes (item, attributes, FALSE)) {
			if (!gnome_keyring_proto_add_utf8_string (result, item->keyring->keyring_name)) {
				return_val = FALSE;
				break;
			}
			gnome_keyring_proto_add_uint32 (result, item->id);
			if (!gnome_keyring_proto_add_utf8_secret (result, item->secret)) {
				return_val = FALSE;
				break;
			}
			if (!gnome_keyring_proto_add_attribute_list (result,
								     item->attributes)) {
				return_val = FALSE;
				break;
			}
		}
	}
	gnome_keyring_attribute_list_free (attributes);
	
	return return_val;
}

typedef struct _FindContext {
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttributeList *hashed;
	GnomeKeyringItemType type;
	GList *access_requests;
	GnomeKeyringApplicationRef *app_ref;
} FindContext;

static gboolean 
find_in_each_keyring (GkrKeyring* keyring, gpointer data)
{
	FindContext* ctx = (FindContext*)data;
	GkrAskRequest *ask;
	GkrKeyringItem *item;
	GList *ilist;
	gboolean ask_keyring = FALSE;
	
	for (ilist = keyring->items; ilist != NULL; ilist = ilist->next) {
		item = ilist->data;
		if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) != (ctx->type & GNOME_KEYRING_ITEM_TYPE_MASK) ||
		    !match_attributes (item, keyring->locked ? ctx->hashed : ctx->attributes, FALSE))
			continue;
			
		if (keyring->locked && !ask_keyring) {
			ask = access_request_from_keyring (ctx->app_ref, keyring, GNOME_KEYRING_ACCESS_READ);
			ctx->access_requests = g_list_prepend (ctx->access_requests, ask);
			ask_keyring = TRUE;
		}
		
		    	
		ask = access_request_from_item (ctx->app_ref, item, GNOME_KEYRING_ACCESS_READ, TRUE);
		ctx->access_requests = g_list_append (ctx->access_requests, ask);
	}
	
	return TRUE;
}

static gboolean
op_find_collect (GkrBuffer *packet, GkrKeyringRequest *req)
{
	FindContext ctx;
	
	memset (&ctx, 0, sizeof (ctx));
	
	if (!gnome_keyring_proto_decode_find (packet,
					      &ctx.type,
					      &ctx.attributes)) {
		return FALSE;
	}

	/* Need at least one attribute to match on */
	if (ctx.attributes->len == 0) {
		gnome_keyring_attribute_list_free (ctx.attributes);
		return FALSE;
	}

	ctx.hashed = gnome_keyring_attributes_hash (ctx.attributes);

	ctx.access_requests = NULL;
	ctx.app_ref = req->app_ref;
	
	gkr_keyrings_foreach (find_in_each_keyring, &ctx);

	gnome_keyring_attribute_list_free (ctx.attributes);
	gnome_keyring_attribute_list_free (ctx.hashed);

	req->ask_requests = ctx.access_requests;
	
	/* Note the number of items found, for later use */
	req->data = GUINT_TO_POINTER (g_list_length (ctx.access_requests));
	
	return TRUE;
}

GnomeKeyringOperationImplementation keyring_ops[] = {
	{ NULL,  op_lock_all_execute }, /* LOCK_ALL */
	{ NULL, op_set_default_keyring_execute}, /* SET_DEFAULT_KEYRING */
	{ NULL, op_get_default_keyring_execute}, /* GET_DEFAULT_KEYRING */
	{ NULL, op_list_keyrings_execute}, /* LIST_KEYRINGS */
	{ op_create_keyring_collect, op_create_keyring_execute}, /* CREATE_KEYRING */
	{ NULL, op_lock_keyring_execute}, /* LOCK_KEYRING */
	{ op_unlock_keyring_collect, op_unlock_keyring_execute}, /* UNLOCK_KEYRING */
	{ NULL, op_delete_keyring_execute}, /* DELETE_KEYRING */
	{ NULL, op_get_keyring_info_execute}, /* GET_KEYRING_INFO */
	{ NULL, op_set_keyring_info_execute}, /* SET_KEYRING_INFO */
	{ op_list_items_collect, op_list_items_execute}, /* LIST_ITEMS */
	{ op_find_collect, op_find_execute }, /* FIND */
	{ op_create_item_collect, op_create_item_execute}, /* CREATE_ITEM */
	{ op_delete_item_collect, op_delete_item_execute}, /* DELETE_ITEM */
	{ op_get_item_info_collect, op_get_item_info_execute}, /* GET_ITEM_INFO */
	{ op_set_item_info_or_attributes_collect, op_set_item_info_execute}, /* SET_ITEM_INFO */
	{ op_get_item_acl_or_attributes_collect, op_get_item_attributes_execute}, /* GET_ITEM_ATTRIBUTES */
	{ op_set_item_info_or_attributes_collect, op_set_item_attributes_execute}, /* SET_ITEM_ATTRIBUTES */
	{ op_get_item_acl_or_attributes_collect, op_get_item_acl_execute}, /* GET_ITEM_ACL */
	{ op_set_item_info_or_attributes_collect, op_set_item_acl_execute}, /* SET_ITEM_ACL */
	{ op_change_keyring_password_collect, op_change_keyring_password_execute }, /*CHANGE_KEYRING_PASSWORD*/
 	{ NULL, op_set_daemon_display_execute}, /* SET_DAEMON_DISPLAY */
	{ op_get_item_info_collect, op_get_item_info_execute}, /* GET_ITEM_INFO_PARTIAL */
};
