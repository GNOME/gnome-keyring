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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <glib.h>

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-proto.h"
#include "gnome-keyring-daemon.h"

#include <gcrypt.h>

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

enum AskType {
	ASK_KEYRING_PASSWORD,
	ASK_ITEM_READ_WRITE_ACCESS,
	ASK_NEW_KEYRING_PASSWORD,
	ASK_ORIGINAL_CHANGE_KEYRING_PASSWORD,
	ASK_CHANGE_KEYRING_PASSWORD,
	ASK_DEFAULT_KEYRING
};

typedef struct {
	GnomeKeyringApplicationRef *app_ref; /* owned by the client object */
	GList *access_requests;
	GnomeKeyringAccessRequest *current_request; /* points into list */
	enum AskType current_ask_type;
	
	GList *denied_keyrings;

	gint ask_pid;
	GString *buffer;
	guint input_watch;
	
	GnomeKeyringRequestAccessCallback  callback;
	gpointer                           callback_data;
} GnomeKeyringAsk;


extern char **environ;

gboolean have_display = FALSE;

GList *outstanding_asks = NULL;

GList *keyrings = NULL;

GkrKeyring *session_keyring;
GkrKeyring *default_keyring;

static GMainLoop *loop = NULL;

static gboolean gnome_keyring_ask_iterate (GnomeKeyringAsk *ask);
static void fixup_for_removed (gpointer keyring, gpointer item, gpointer unused);

void
gnome_keyring_access_request_free (GnomeKeyringAccessRequest *access_request)
{
	g_free (access_request->new_keyring);
	gnome_keyring_free_password (access_request->password);

	if (access_request->keyring)
		g_object_unref (access_request->keyring);
	if (access_request->item)
		g_object_unref (access_request->item);

	g_free (access_request);
	
}

GnomeKeyringAccessRequest *
gnome_keyring_access_request_copy (GnomeKeyringAccessRequest *access_request)
{
	GnomeKeyringAccessRequest *ret;
	
	ret = g_new (GnomeKeyringAccessRequest, 1);
	
	/* shallow copy */
	*ret = *access_request;

	ret->password = g_strdup (ret->password);
	ret->new_keyring = g_strdup (ret->new_keyring);
	
	if (ret->keyring)
		g_object_ref (ret->keyring);
	if (ret->item)
		g_object_ref (ret->item);
	
	return ret;
}

void
gnome_keyring_access_request_list_free (GList *access_requests)
{
	g_list_foreach (access_requests, (GFunc) gnome_keyring_access_request_free, NULL);
	g_list_free (access_requests);
}

GList *
gnome_keyring_access_request_list_copy (GList *list)
{
	GList *ret, *l;

	ret = g_list_copy (list);
	for (l = ret; l != NULL; l = l->next) {
		l->data = gnome_keyring_access_request_copy (l->data);
	}

	return ret;
}


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
request_allowed_for_app (GnomeKeyringAccessRequest *request,
			 GnomeKeyringApplicationRef *app_ref,
			 GList *denied_keyrings,
			 gboolean *currently_asking)
{
	GnomeKeyringAccessControl *ac;
	GList *l;

	if (currently_asking) {
		*currently_asking = FALSE;
	}

	if (request->granted) {
		return TRUE;
	}
	
	if (request->keyring != NULL) {
		if (request->keyring->locked) {
			if (currently_asking) {
				*currently_asking = request->keyring->asking_password;
			}
			return FALSE;
		}
		/* TODO: verify app ACL vs keyring?? */
		return TRUE;

	} else if (request->item != NULL) {
		if (request->item->locked) {
			if (currently_asking) {
				*currently_asking = request->item->keyring->asking_password;
			}
			return FALSE;
		}

		/* Is it only basic info read access (no secret)? */
		if(request->request_type == GNOME_KEYRING_ACCESS_REQUEST_ITEM && 
		   request->access_type == GNOME_KEYRING_ACCESS_READ) {	

			/* If item is not marked as an application secret then automatic access */
			if ((request->item->type & GNOME_KEYRING_ITEM_APPLICATION_SECRET) == 0)
				return TRUE;
		}
			
		/* Otherwise full access to secret, or modify access we check the calling application */
		for (l = request->item->acl; l != NULL; l = l->next) {
			ac = l->data;
			if (app_ref_match (app_ref, ac->application) &&
			    (ac->types_allowed & request->access_type) == request->access_type) {
				return TRUE;
			}
		}
	}
	/* password always fails until granted */
	return FALSE;
}

static void
gnome_keyring_ask_kill (GnomeKeyringAsk *ask)
{
	GkrKeyring *keyring;
	
	if (ask->input_watch != 0) {

		if (ask->current_ask_type == ASK_KEYRING_PASSWORD) {
			if (ask->current_request->keyring != NULL) {
				keyring = ask->current_request->keyring;
			} else {
				keyring = ask->current_request->item->keyring;
			}
			if (keyring) {
				keyring->asking_password = FALSE;
			}
		}
		
		g_source_remove (ask->input_watch);
		ask->input_watch = 0;
	}
	if (ask->ask_pid != 0) {
		kill (ask->ask_pid, SIGKILL);
		ask->ask_pid = 0;
	}
}

static void
gnome_keyring_ask_free (GnomeKeyringAsk *ask)
{
	outstanding_asks = g_list_remove (outstanding_asks, ask);

	gnome_keyring_ask_kill (ask);
	
	gnome_keyring_access_request_list_free (ask->access_requests);
	g_list_free (ask->denied_keyrings);
	g_string_free (ask->buffer, TRUE);
	g_free (ask);
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

static GnomeKeyringAccessRequest *
access_request_from_item (GkrKeyringItem *item)
{
	GnomeKeyringAccessRequest *access_request;
	
	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_ITEM;
	access_request->access_type = GNOME_KEYRING_ACCESS_READ; /* Always only read access */
	access_request->item = item;
	
	g_object_ref (item);
	
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_from_item_with_secret (GkrKeyringItem *item,
			  	      GnomeKeyringAccessType access_type)
{
	GnomeKeyringAccessRequest *access_request;

	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_ITEM_SECRET;
	access_request->access_type = access_type;
	access_request->item = item;
	
	g_object_ref (item);
	
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_from_keyring (GkrKeyring *keyring,
			     GnomeKeyringAccessType access_type)
{
	GnomeKeyringAccessRequest *access_request;
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_KEYRING;
	access_request->access_type = access_type;
	access_request->keyring = keyring;
	
	g_object_ref (keyring);
	
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_for_new_keyring_password (const char *keyring_name)
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_NEW_KEYRING_PASSWORD;
	access_request->new_keyring = g_strdup (keyring_name);
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_for_change_keyring_password (const char *keyring_name,
					    gboolean need_original)
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	if (need_original) {
		access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_ORIGINAL_CHANGE_KEYRING_PASSWORD;
	} else {
		access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_CHANGE_KEYRING_PASSWORD;
	}
	access_request->new_keyring = g_strdup (keyring_name);
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_default_keyring (void)
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING;
	return access_request;
}


GkrKeyring *
find_keyring (const char *name)
{
	GList *l;
	GkrKeyring *keyring;

	if (name == NULL)
		return NULL;

	for (l = keyrings; l != NULL; l = l->next) {
		keyring = l->data;

		if (strcmp (keyring->keyring_name, name) == 0) {
			return keyring;
		}
	}
	
	return NULL;
}


static GnomeKeyringResult
change_keyring_password (GkrKeyring *keyring,  const char *password)
{
	if (keyring->locked) {
		return GNOME_KEYRING_RESULT_DENIED;
	} else { 
		keyring->password = g_strdup (password);
		gkr_keyring_save_to_disk (keyring);
		return GNOME_KEYRING_RESULT_OK;
	}
}

static GnomeKeyringResult
unlock_keyring (GkrKeyring *keyring, const char *password)
{
	if (!keyring->locked) {
		return GNOME_KEYRING_RESULT_ALREADY_UNLOCKED;
	} else {
		g_assert (keyring->password == NULL);
		
		keyring->password = g_strdup (password);
		if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
			g_free (keyring->password);
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
}

void 
gkr_daemon_add_keyring (GkrKeyring *keyring)
{
	g_assert (GKR_IS_KEYRING (keyring));
	
	/* Can't add the same keyring twice */
	g_assert (g_list_find (keyrings, keyring) == NULL);
	
	keyrings = g_list_prepend (keyrings, keyring);
	g_object_ref (keyring);
	
	/* Cancels any ask requests for an item when it is removed */
	g_signal_connect (keyring, "item-removed", 
	                  G_CALLBACK (fixup_for_removed), NULL);
}

void 
gkr_daemon_remove_keyring (GkrKeyring *keyring)
{
	g_assert (GKR_IS_KEYRING (keyring));
	
	if (g_list_find (keyrings, keyring)) {
		
		/* Connected in gkr_daemon_add_keyring () */
		g_signal_handlers_disconnect_by_func (keyring, fixup_for_removed, NULL);
		
		keyrings = g_list_remove (keyrings, keyring);

		/* Stop anything happening with this keyring */
		fixup_for_removed ((gpointer)keyring, NULL, NULL);
		
		g_object_unref (keyring);
	}
	
	if (keyring == default_keyring)
		default_keyring = NULL;
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
	
	g_free (keyring->password);
	keyring->password = NULL;
	if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
		/* Failed to re-read, remove the keyring */
		g_warning ("Couldn't re-read keyring %s\n", keyring->keyring_name);
		gkr_daemon_remove_keyring (keyring);
	}
}

static gboolean
op_lock_keyring_execute (GString *packet,
			 GString *result,
			 GnomeKeyringApplicationRef *app_ref,
			 GList *access_requests)
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
		keyring = default_keyring;
	} else {
		keyring = find_keyring (keyring_name);
	}
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		lock_keyring (keyring);
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	}
	
	return TRUE;
}

static gboolean
op_lock_all_execute (GString *packet,
		     GString *result,
		     GnomeKeyringApplicationRef *app_ref,
		     GList *access_requests)
{
	GList *l;
	GkrKeyring *keyring;

	for (l = keyrings; l != NULL; l = l->next) {
		keyring = l->data;
		lock_keyring (keyring);
	}
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	return TRUE;
}

static gboolean
op_set_default_keyring_execute (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests)
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
		set_default_keyring (NULL);
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	} else {
		keyring = find_keyring (keyring_name);
		if (keyring == NULL) {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		} else {
			set_default_keyring (keyring);
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
		}
	}
	
	g_free (keyring_name);
	
	return TRUE;
}

static gboolean
op_get_default_keyring_execute (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests)
{
	char *name;
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	name = NULL;
	if (default_keyring != NULL) {
		name = default_keyring->keyring_name;
	}

	if (!gnome_keyring_proto_add_utf8_string (result, name)) {
		return FALSE;
	}
	
	return TRUE;
}


static gboolean
op_list_keyrings_execute (GString *packet,
			  GString *result,
			  GnomeKeyringApplicationRef *app_ref,
			  GList *access_requests)
{
	GList *l;
	GkrKeyring *keyring;
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	gnome_keyring_proto_add_uint32 (result, g_list_length (keyrings));
	for (l = keyrings; l != NULL; l = l->next) {
		keyring = l->data;
		
		if (!gnome_keyring_proto_add_utf8_string (result, keyring->keyring_name)) {
			return FALSE;
		}
	}
	
	return TRUE;
}


static gboolean
op_set_keyring_info_execute (GString *packet,
			     GString *result,
			     GnomeKeyringApplicationRef *app_ref,
			     GList *access_requests)
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
	
	keyring = find_keyring (keyring_name);
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
op_get_keyring_info_execute (GString *packet,
			     GString *result,
			     GnomeKeyringApplicationRef *app_ref,
			     GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}
	
	keyring = find_keyring (keyring_name);
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
op_create_keyring_collect (GString *packet,
			   GList **access_requests_out)
{
	GList *access_requests;
	GnomeKeyringOpCode opcode;
	char *keyring_name, *password;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string_string (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}

	access_requests = NULL;
	
	if (keyring_name == NULL) {
		/* param error */
		goto out;
	}
	
	keyring = find_keyring (keyring_name);
	if (keyring != NULL) {
		/* already exist */
		goto out;
	}
	
	if (password == NULL) {
		/* Let user pick password */
		access_requests =
			g_list_prepend (access_requests,
					access_request_for_new_keyring_password (keyring_name));
	}

 out:
	*access_requests_out = access_requests;
	
	g_free (keyring_name);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static GkrKeyring *
create_new_keyring (const char *keyring_name, const char *password)
{
	GkrKeyring *keyring;
	
	keyring = gkr_keyring_new (keyring_name, NULL);
	if (keyring != NULL) {
		keyring->file = get_default_keyring_file_for_name (keyring_name);
		keyring->locked = FALSE;
		keyring->password = g_strdup (password);
		gkr_keyring_save_to_disk (keyring);
		
		/* Add to our main list */
		gkr_daemon_add_keyring (keyring);
		
		/* Let go of the initial reference to this object */
		g_object_unref (keyring);
		g_assert (GKR_IS_KEYRING (keyring));
	}
	return keyring;

}


static gboolean
op_create_keyring_execute (GString *packet,
			   GString *result,
			   GnomeKeyringApplicationRef *app_ref,
			   GList *access_requests)
{
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GnomeKeyringAccessRequest *req;
	
	if (!gnome_keyring_proto_decode_op_string_string (packet,
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
	
	keyring = find_keyring (keyring_name);
	if (keyring != NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_ALREADY_EXISTS);
		goto out;
	}
	
	if (password == NULL) {
		if (access_requests != NULL) {
			req = access_requests->data;
			password = g_strdup (req->password);
		}
	}
	
	if (password == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	keyring = create_new_keyring (keyring_name, password);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
 out:
	g_free (keyring_name);
	gnome_keyring_free_password (password);

	return TRUE;
}


static gboolean
op_unlock_keyring_execute (GString *packet,
			   GString *result,
			   GnomeKeyringApplicationRef *app_ref,
			   GList *access_requests)
{
	char *keyring_name, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gnome_keyring_proto_decode_op_string_string (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_UNLOCK_KEYRING);
	
	if (keyring_name == NULL) {
		keyring = default_keyring;
	} else {
		keyring = find_keyring (keyring_name);
	}
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		gnome_keyring_proto_add_uint32 (result,
						unlock_keyring (keyring, password));
	}
	
	g_free (keyring_name);
	gnome_keyring_free_password (password);

	return TRUE;
}


static gboolean
op_delete_keyring_execute (GString *packet,
			   GString *result,
			   GnomeKeyringApplicationRef *app_ref,
			   GList *access_requests)
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
	
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	} else {
		if (!gkr_keyring_remove_from_disk (keyring)) 
			res = GNOME_KEYRING_RESULT_DENIED;
		else
			res = GNOME_KEYRING_RESULT_OK;
		gnome_keyring_proto_add_uint32 (result, res);
	}
	
	g_free (keyring_name);
	
	if (res == GNOME_KEYRING_RESULT_OK)
		gkr_daemon_remove_keyring (keyring);

	return TRUE;
}

static gboolean
op_change_keyring_password_collect (GString *packet,
				    GList **access_requests_out)
{
	GList *access_requests;
	GnomeKeyringOpCode opcode;
	char *keyring_name, *original, *password;
	GkrKeyring *keyring;
	
	if (!gnome_keyring_proto_decode_op_string_string_string (packet,
							  &opcode,
							  &keyring_name,
							  &original,
							  &password)) {
		return FALSE;
	}

	access_requests = NULL;
	
	if (keyring_name == NULL) {
		keyring_name = "default";
	}
	
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		/* don't exist */
		return FALSE;
	}
	
	if (password == NULL) {
		if (original == NULL ) {
			/* Prompt for original and Let user pick password */
			access_requests =
				g_list_prepend (access_requests,
						access_request_for_change_keyring_password (keyring_name, TRUE));
		} else {
			/* Use original given to us Let user pick password */
			access_requests =
				g_list_prepend (access_requests,
						access_request_for_change_keyring_password (keyring_name, FALSE));
		}
	}

	*access_requests_out = access_requests;
	
	g_free (keyring_name);
	gnome_keyring_free_password (original);
	gnome_keyring_free_password (password);
	
	return TRUE;
}

static gboolean
op_change_keyring_password_execute (GString *packet,
			   GString *result,
			   GnomeKeyringApplicationRef *app_ref,
			   GList *access_requests)
{
	char *keyring_name, *original, *password;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GnomeKeyringAccessRequest *req;
	
	if (!gnome_keyring_proto_decode_op_string_string_string (packet,
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
	
	keyring = find_keyring (keyring_name);
	
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	if (original == NULL) {
		if (access_requests != NULL) {
			req = access_requests->data;
			original = g_strdup (req->original);
		}
	}

	if (original ==NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
	
	lock_keyring(keyring);
	
	if ( unlock_keyring(keyring, original) != GNOME_KEYRING_RESULT_OK ) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	
	if (password == NULL) {
		if (access_requests != NULL) {
			req = access_requests->data;
			password = g_strdup (req->password);
		}
	}
	
	if (password == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
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
op_list_items_collect (GString *packet,
			GList **access_requests_out)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GnomeKeyringOpCode opcode;
	GList *access_requests;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	access_requests = NULL;
	
	if (keyring_name != NULL) {
		keyring = find_keyring (keyring_name);
		if (keyring != NULL) {
			access_requests =
				g_list_prepend (access_requests,
						access_request_from_keyring (keyring, GNOME_KEYRING_ACCESS_READ));
		}
	}
	
	g_free (keyring_name);

	*access_requests_out = access_requests;
	return TRUE;
}

static gboolean
op_list_items_execute (GString *packet,
		       GString *result,
		       GnomeKeyringApplicationRef *app_ref,
		       GList *access_requests)
{
	GkrKeyring *keyring;
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GkrKeyringItem *item;
	GList *l, *items;
	GnomeKeyringAccessRequest *req, *list_req;
	
	if (!gnome_keyring_proto_decode_op_string (packet,
						   &opcode,
						   &keyring_name)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		gnome_keyring_proto_add_uint32 (result, 0);
	} else if (find_keyring (keyring_name) == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		gnome_keyring_proto_add_uint32 (result, 0);
	} else if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		gnome_keyring_proto_add_uint32 (result, 0);
	} else {
		req = access_requests->data;
		keyring = req->keyring;
		g_assert (keyring != NULL);

		if (keyring->locked) {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
			gnome_keyring_proto_add_uint32 (result, 0);
		} else {
			gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

			/* 
			 * Request access to these items. This cannot be done earlier in 
			 * op_list_items_collect because the keyring may have been locked.
			 */
			list_req = access_request_from_item (NULL);
			
			items = NULL;
			for (l = keyring->items; l != NULL; l = l->next) {
				list_req->item = l->data;
				list_req->granted = FALSE;
				if (request_allowed_for_app (list_req, app_ref, NULL, NULL))
					items = g_list_prepend (items, list_req->item);
			}
			items = g_list_reverse (items);

			gnome_keyring_access_request_free (list_req);

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
op_create_item_collect (GString *packet,
			GList **access_requests_out)
{
	char *keyring_name;
	GList *access_requests;
	GkrKeyring *keyring;
	GnomeKeyringAttributeList *attributes;
	guint32 type;
	gboolean update_if_exists;
	GnomeKeyringAttributeList *hashed;
	GList *ilist;
	gboolean found_existing;
	GkrKeyringItem *item;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_create_item (packet,
						     &keyring_name, NULL,
						     &attributes, NULL,
						     (GnomeKeyringItemType *) &type,
						     &update_if_exists)) {
		return FALSE;
	}

	access_requests = NULL;
	
	found_existing = FALSE;

	if (keyring_name == NULL) {
		keyring = default_keyring;
		
		if (keyring == NULL) {
			access_requests =
				g_list_prepend (access_requests,
						access_request_default_keyring ());
		}
	} else {
		keyring = find_keyring (keyring_name);
	}
	
	if (update_if_exists && keyring != NULL) {
		hashed = gnome_keyring_attributes_hash (attributes);

		for (ilist = keyring->items; ilist != NULL; ilist = ilist->next) {
			item = ilist->data;
			if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) == (type & GNOME_KEYRING_ITEM_TYPE_MASK) &&
			    match_attributes (item, keyring->locked ? hashed : attributes, TRUE)) {
				found_existing = TRUE;
				access_request =
					access_request_from_item_with_secret (item, GNOME_KEYRING_ACCESS_WRITE);
				access_requests = g_list_prepend (access_requests,
								  access_request);
				break;
			}
		}
		
		gnome_keyring_attribute_list_free (hashed);
	}
	gnome_keyring_attribute_list_free (attributes);

	if (!found_existing && keyring != NULL) {
		access_requests =
			g_list_prepend (access_requests,
					access_request_from_keyring (keyring, GNOME_KEYRING_ACCESS_WRITE));
	}
	
	g_free (keyring_name);
	*access_requests_out = access_requests;
	
	return TRUE;
}

static gboolean
op_create_item_execute (GString *packet,
			GString *result,
			GnomeKeyringApplicationRef *app_ref,
			GList *access_requests)
{
	char *keyring_name, *display_name, *secret;
	GnomeKeyringAttributeList *attributes;
	GkrKeyringItem *item;
	GkrKeyring *keyring;
	guint32 type;
	GnomeKeyringResult res;
	guint32 id;
	gboolean update_if_exists;
	GnomeKeyringAccessRequest *access_request;

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

	if (keyring_name == NULL) {
		keyring = default_keyring;
	} else {
		keyring = find_keyring (keyring_name);
	}

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

	if (access_requests == NULL) {
		res = GNOME_KEYRING_RESULT_DENIED;
		goto bail;
	}
	item = NULL;
	access_request = access_requests->data;
	if (access_request->item != NULL) {
		item = access_request->item;
	}

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
	g_free (item->secret);
	item->secret = g_strdup (secret);
	if (item->attributes != NULL) {
		gnome_keyring_attribute_list_free (item->attributes);
	}
	item->attributes = gnome_keyring_attribute_list_copy (attributes);
	add_item_acl (item, app_ref,
		      GNOME_KEYRING_ACCESS_READ |
		      GNOME_KEYRING_ACCESS_WRITE |
		      GNOME_KEYRING_ACCESS_REMOVE);
	
	id = item->id;
	
	gkr_keyring_save_to_disk (keyring);

 bail:	
	g_free (keyring_name);
	g_free (display_name);
	g_free (secret);
	gnome_keyring_attribute_list_free (attributes);
	
	gnome_keyring_proto_add_uint32 (result, res);
	gnome_keyring_proto_add_uint32 (result, id);
	return TRUE;
}


static gboolean
op_delete_item_collect (GString *packet,
			GList **access_requests_out)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	GList *access_requests;

	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	access_requests = NULL;
	if (keyring_name != NULL) {
		keyring = find_keyring (keyring_name);
		if (keyring != NULL) {
			item = gkr_keyring_find_item (keyring, item_id);
			if (item != NULL) {
				access_request =
					access_request_from_item_with_secret (item,
								  GNOME_KEYRING_ACCESS_REMOVE);
				access_requests = g_list_prepend (access_requests,
								  access_request);
			}
		}
	}

	*access_requests_out = access_requests;
	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_delete_item_execute (GString *packet,
			GString *result,
			GnomeKeyringApplicationRef *app_ref,
			GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->keyring != keyring ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gkr_keyring_remove_item (keyring, item);
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gkr_keyring_save_to_disk (keyring);

 out:
	
	g_free (keyring_name);
	return TRUE;
}



static gboolean
op_get_item_info_collect (GString *packet, GList **access_requests_out)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id, flags;
	GnomeKeyringAccessRequest *access_request;
	GList *access_requests;

	if (!gnome_keyring_proto_decode_get_item_info (packet, &opcode, &keyring_name, 
						       &item_id, &flags)) {
		return FALSE;
	}

	access_requests = NULL;
	if (keyring_name != NULL) {
		keyring = find_keyring (keyring_name);
		if (keyring != NULL) {
			item = gkr_keyring_find_item (keyring, item_id);
			if (item != NULL) {
				/* Request access based on what parts were desired */
				if ((flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET) {
					access_request = access_request_from_item_with_secret (item,
									  GNOME_KEYRING_ACCESS_READ);
				} else {
					access_request = access_request_from_item (item);
				}
				access_requests = g_list_prepend (access_requests,
								  access_request);
			}
		}
	}

	*access_requests_out = access_requests;
	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_get_item_info_execute (GString *packet,
			  GString *result,
			  GnomeKeyringApplicationRef *app_ref,
			  GList *access_requests)
{
	char *keyring_name, *secret;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id, flags;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_get_item_info (packet, &opcode, &keyring_name,
						       &item_id, &flags)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gnome_keyring_proto_add_uint32 (result, item->type);
	if (!gnome_keyring_proto_add_utf8_string (result, item->display_name)) {
		return FALSE;
	}

	/* Only return the secret if it was requested */
	secret = NULL;
	if ((flags & GNOME_KEYRING_ITEM_INFO_SECRET) == GNOME_KEYRING_ITEM_INFO_SECRET) {
		g_assert(access_request->request_type == GNOME_KEYRING_ACCESS_REQUEST_ITEM_SECRET);
		secret = item->secret;
	}

	/* Always put the secret string or NULL in the results for compatibility */
	if (!gnome_keyring_proto_add_utf8_string (result, secret)) {
		return FALSE;
	}

	gnome_keyring_proto_add_time (result, keyring->mtime);
	gnome_keyring_proto_add_time (result, keyring->ctime);
	
out:
	
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_get_item_acl_or_attributes_collect (GString *packet,
					GList **access_requests_out)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	GList *access_requests;

	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	access_requests = NULL;
	if (keyring_name != NULL) {
		keyring = find_keyring (keyring_name);
		if (keyring != NULL) {
			item = gkr_keyring_find_item (keyring, item_id);
			if (item != NULL) {
				access_request = access_request_from_item (item);
				access_requests = g_list_prepend (access_requests,
								  access_request);
			}
		}
	}

	*access_requests_out = access_requests;
	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_get_item_attributes_execute (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

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
op_get_item_acl_execute (GString *packet,
			 GString *result,
			 GnomeKeyringApplicationRef *app_ref,
			 GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

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
op_set_item_acl_execute (GString *packet,
			 GString *result,
			 GnomeKeyringApplicationRef *app_ref,
			 GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	GList *acl;
	
	if (!gnome_keyring_proto_decode_set_acl (packet,
						 &keyring_name,
						 &item_id,
						 &acl)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	gnome_keyring_acl_free (item->acl);
	item->acl = gnome_keyring_acl_copy (acl);

out:
	gnome_keyring_acl_free (acl);
	g_free (keyring_name);
	return TRUE;
}

static gboolean
op_set_item_info_or_attributes_collect (GString *packet,
					GList **access_requests_out)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GnomeKeyringOpCode opcode;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	GList *access_requests;

	
	if (!gnome_keyring_proto_decode_op_string_int (packet,
						       &opcode,
						       &keyring_name,
						       &item_id)) {
		return FALSE;
	}

	access_requests = NULL;
	if (keyring_name != NULL) {
		keyring = find_keyring (keyring_name);
		if (keyring != NULL) {
			item = gkr_keyring_find_item (keyring, item_id);
			if (item != NULL) {
				access_request =
					access_request_from_item_with_secret (item,
								  GNOME_KEYRING_ACCESS_WRITE);
				access_requests = g_list_prepend (access_requests,
								  access_request);
			}
		}
	}

	*access_requests_out = access_requests;
	g_free (keyring_name);
	
	return TRUE;
	
}

static gboolean
op_set_item_info_execute (GString *packet,
			  GString *result,
			  GnomeKeyringApplicationRef *app_ref,
			  GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id, type;
	GnomeKeyringAccessRequest *access_request;
	char *item_name, *secret;
	
	if (!gnome_keyring_proto_decode_set_item_info (packet,
						       &keyring_name,
						       &item_id,
						       (GnomeKeyringItemType *) &type,
						       &item_name,
						       &secret)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->keyring != keyring ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	if ((type & GNOME_KEYRING_ITEM_TYPE_MASK) != GNOME_KEYRING_ITEM_NO_TYPE) {
		item->type = type;
	}
	if (item_name != NULL) {
		g_free (item->display_name);
		item->display_name = g_strdup (item_name);
	}
	if (secret != NULL) {
		g_free (item->secret);
		item->secret = g_strdup (secret);
	}
	
out:
	
	g_free (keyring_name);
	g_free (item_name);
	gnome_keyring_free_password (secret);
	return TRUE;
}

static gboolean
op_set_daemon_display_execute (GString *packet,
			       GString *result,
			       GnomeKeyringApplicationRef *app_ref,
			       GList *access_requests)
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

       if (!have_display && (g_strrstr (display, ":") != NULL)) {
               g_setenv ( "DISPLAY", display, TRUE );
               have_display = TRUE;
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
op_set_item_attributes_execute (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests)
{
	char *keyring_name;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	guint32 item_id;
	GnomeKeyringAccessRequest *access_request;
	GnomeKeyringAttributeList *attributes;
	
	if (!gnome_keyring_proto_decode_set_attributes (packet,
							&keyring_name,
							&item_id,
							&attributes)) {
		return FALSE;
	}

	if (keyring_name == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_BAD_ARGUMENTS);
		goto out;
	}
		
	keyring = find_keyring (keyring_name);
	if (keyring == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
		goto out;
	}

	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}

	access_request = access_requests->data;

	if (access_request->item == NULL ||
	    access_request->item->keyring != keyring ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

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
	const GnomeKeyringAccessRequest *access_request;

	
	matching = user_data;

	access_request = a;
	a_unmatched = unmatched_attributes (access_request->item->attributes, matching);
	access_request = b;
	b_unmatched = unmatched_attributes (access_request->item->attributes, matching);

	if (a_unmatched < b_unmatched) {
		return -1;
	} else if (a_unmatched == b_unmatched) {
		return 0;
	} else {
		return 1;
	}
}


static gboolean
op_find_execute (GString *packet,
		 GString *result,
		 GnomeKeyringApplicationRef *app_ref,
		 GList *access_requests)
{
	GList *l;
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAccessRequest *access_request;
	gboolean return_val;
	GkrKeyringItem *item;
	GnomeKeyringItemType type;
	
	if (access_requests == NULL) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
	} else {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	}
	
	if (!gnome_keyring_proto_decode_find (packet,
					      &type,
					      &attributes)) {
		return FALSE;
	}
	
	access_requests = g_list_sort_with_data (access_requests,
						 sort_found, attributes);
	
	/* The attributes might have changed since we matched them, rematch */
	return_val = TRUE;
	for (l = access_requests; l != NULL; l = l->next) {
		access_request = l->data;
		item = access_request->item;
		if (item != NULL &&
		    (item->type & GNOME_KEYRING_ITEM_TYPE_MASK) == (type & GNOME_KEYRING_ITEM_TYPE_MASK) &&
		    !item->locked &&
		    match_attributes (item, attributes, FALSE)) {
			if (!gnome_keyring_proto_add_utf8_string (result, item->keyring->keyring_name)) {
				return_val = FALSE;
				break;
			}
			gnome_keyring_proto_add_uint32 (result, item->id);
			if (!gnome_keyring_proto_add_utf8_string (result, item->secret)) {
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

static gboolean
op_find_collect (GString *packet,
		 GList **access_requests_out)
{
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttributeList *hashed;
	GList *klist, *ilist;
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	GList *access_requests;
	GnomeKeyringAccessRequest *access_request;
	GnomeKeyringItemType type;
	
	if (!gnome_keyring_proto_decode_find (packet,
					      &type,
					      &attributes)) {
		return FALSE;
	}

	/* Need at least one attribute to match on */
	if (attributes->len == 0) {
		gnome_keyring_attribute_list_free (attributes);
		return FALSE;
	}

	hashed = gnome_keyring_attributes_hash (attributes);

	access_requests = NULL;
	for (klist = keyrings; klist != NULL; klist = klist->next) {
		keyring = klist->data;
		for (ilist = keyring->items; ilist != NULL; ilist = ilist->next) {
			item = ilist->data;
			if ((item->type & GNOME_KEYRING_ITEM_TYPE_MASK) == (type & GNOME_KEYRING_ITEM_TYPE_MASK) &&
			    match_attributes (item, keyring->locked ? hashed : attributes, FALSE)) {
				access_request =
				  access_request_from_item_with_secret (item, GNOME_KEYRING_ACCESS_READ);
				access_requests = g_list_prepend (access_requests,
								  access_request);
			}
		}
	}
	gnome_keyring_attribute_list_free (attributes);
	gnome_keyring_attribute_list_free (hashed);

	*access_requests_out = access_requests;
	return TRUE;
}

static void
finish_ask_io (GnomeKeyringAsk *ask,
	       gboolean failed)
{
	gchar **lines;
	int response;
	char *str;
	char *str1;
	GkrKeyring *keyring;
	GkrKeyringItem *item;

	if (ask->current_ask_type == ASK_KEYRING_PASSWORD) {
		if (ask->current_request->keyring != NULL) {
			keyring = ask->current_request->keyring;
		} else {
			keyring = ask->current_request->item->keyring;
		}
		if (keyring) {
			keyring->asking_password = FALSE;
		}
	}
	    
	ask->input_watch = 0;
	ask->ask_pid = 0;
	
	/* default for failed requests */
	response = GNOME_KEYRING_ASK_RESPONSE_FAILURE;
	str = NULL;
	str1 = NULL;

	if (!failed) {
		lines = g_strsplit (ask->buffer->str, "\n", 3);
		if (lines[0]) {
			response = atol (lines[0]);
			if (lines[1]) {
				str = g_strdup (lines[1]);
				if (lines[2]) {
					str1 = g_strdup (lines[2]);
				}
			} 
		}
		g_strfreev (lines);
	}

	if (response == GNOME_KEYRING_ASK_RESPONSE_FAILURE ||
	    response == GNOME_KEYRING_ASK_RESPONSE_DENY) {
			ask->access_requests = g_list_remove (ask->access_requests, ask->current_request);
			gnome_keyring_access_request_free (ask->current_request);
	} else {
		switch (ask->current_ask_type) {
		case ASK_DEFAULT_KEYRING:
			if (str && strlen (str) > 0) {
				keyring = create_new_keyring ("default", str);
				if (keyring != NULL) {
					default_keyring = keyring;
					/* TODO: store the name of the default keyring */
				}
				ask->current_request->granted = TRUE;
			}
			break;
		case ASK_NEW_KEYRING_PASSWORD:
			if (str && strlen (str) > 0) {
				ask->current_request->password = g_strdup (str);
				ask->current_request->granted = TRUE;
			}
			break;
		case ASK_ORIGINAL_CHANGE_KEYRING_PASSWORD:
			if (str && strlen (str) > 0 && str1 && strlen (str1) > 0) {
				ask->current_request->original = g_strdup (str);
				ask->current_request->password = g_strdup (str1);
				ask->current_request->granted = TRUE;
			}
			break;
		case ASK_CHANGE_KEYRING_PASSWORD:
			if (str && strlen (str) > 0) {
				ask->current_request->password = g_strdup (str);
				ask->current_request->granted = TRUE;
			}
			break;
		case ASK_KEYRING_PASSWORD:
			if (ask->current_request->keyring != NULL) {
				keyring = ask->current_request->keyring;
			} else {
				keyring = ask->current_request->item->keyring;
			}
			if (keyring->locked) {
				unlock_keyring (keyring, str);
				if (keyring->locked) {
					/* will re-ask */
				}
			}
			/* ok, will ask for access if item */
			break;
		case ASK_ITEM_READ_WRITE_ACCESS:
			item = ask->current_request->item;
			keyring = ask->current_request->item->keyring;
			g_assert (item != NULL);
			if (response == GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER) {
				add_item_acl (item, ask->app_ref,
					      GNOME_KEYRING_ACCESS_READ |
					      GNOME_KEYRING_ACCESS_WRITE |
					      GNOME_KEYRING_ACCESS_REMOVE);
				gkr_keyring_save_to_disk (keyring);
			}
			ask->current_request->granted = TRUE;
			/* ok */
			break;
		default:
			g_assert_not_reached ();
		}
	}
	
	g_free (str);

	/* iterate */
	gnome_keyring_ask_iterate (ask);
}

static gboolean
ask_io (GIOChannel  *channel,
	GIOCondition cond,
	gpointer     callback_data)
{
	char buffer[1024];
	int res;
	int fd;
	GnomeKeyringAsk *ask;

	ask = callback_data;

	fd = g_io_channel_unix_get_fd (channel);
	res = read (fd, buffer, sizeof (buffer));
	if (res < 0) {
		if (errno != EINTR &&
		    errno != EAGAIN) {
			finish_ask_io (ask, TRUE);
			return FALSE;
		}
	} else if (res == 0) {
		finish_ask_io (ask, FALSE);
		return FALSE;
	} else {
		g_string_append_len (ask->buffer,
				     buffer, res);
	}
	return TRUE;
}

static gboolean
launch_ask_helper (GnomeKeyringAsk *ask,
		   enum AskType ask_type)
{
	GnomeKeyringAccessRequest *request;
	GnomeKeyringApplicationRef *app_ref;
	GkrKeyring *keyring;
	GIOChannel *channel;
	char **envp;
	int i, n;
	int stdout_fd;
	GError *error;
	char *argv[] = {
		LIBEXECDIR "/gnome-keyring-ask",
		NULL,
		NULL,
	};
	gboolean res;

	request = ask->current_request;
	app_ref = ask->app_ref;

	i = 0;
	while (environ[i]) {
		++i;
	}
	n = i;
	envp = g_new (char*, n + 1 + 4);

	for (i = 0; i < n; i++) {
		envp[i] = g_strdup (environ[i]);
	}
	if (app_ref->display_name != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_APP_NAME=%s", ask->app_ref->display_name);
	}
	if (app_ref->pathname != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_APP_PATH=%s", ask->app_ref->pathname);
	}
	keyring = NULL;
	if (request->item != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->item->keyring->keyring_name ?
		                                               request->item->keyring->keyring_name : "");
		envp[i++] = g_strdup_printf("ITEM_NAME=%s", request->item->display_name ? 
		                                            request->item->display_name : "");
		keyring = request->item->keyring;
	} else if (request->keyring != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->keyring->keyring_name ? 
                                                               request->keyring->keyring_name : "");
		request->keyring->asking_password = TRUE;
		keyring = request->keyring;
	} else  if (request->new_keyring != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->new_keyring);
	}
	
	envp[i++] = NULL;

	error = NULL;
	if (ask_type == ASK_KEYRING_PASSWORD) {
		argv[1] = "-k";
	} else if (ask_type == ASK_NEW_KEYRING_PASSWORD) {
		argv[1] = "-n";
	} else if (ask_type == ASK_CHANGE_KEYRING_PASSWORD) {
		argv[1] = "-c";
	} else if (ask_type == ASK_ORIGINAL_CHANGE_KEYRING_PASSWORD) {
		argv[1] = "-o";
	} else if (ask_type == ASK_ITEM_READ_WRITE_ACCESS) {
		argv[1] = "-i";
	} else if (ask_type == ASK_DEFAULT_KEYRING) {
		argv[1] = "-d";
	} else {
		g_assert_not_reached ();
	}
	
	ask->current_ask_type = ask_type;
	
	res = FALSE;
	g_string_truncate (ask->buffer, 0);
	if (g_spawn_async_with_pipes (NULL,
				      argv,
				      envp,
				      0,
				      NULL, NULL,
				      &ask->ask_pid,
				      NULL,
				      &stdout_fd,
				      NULL,
				      &error)) {
		if (keyring && ask_type == ASK_KEYRING_PASSWORD) {
			keyring->asking_password = TRUE;
		}
		channel = g_io_channel_unix_new (stdout_fd);
		ask->input_watch = g_io_add_watch (channel, G_IO_IN | G_IO_HUP,
						   ask_io, ask);
		g_io_channel_unref (channel);
		res = TRUE;
	} 
	
	g_strfreev (envp);

	return res;
}

static void
schedule_ask (GnomeKeyringAsk *ask)
{
	GnomeKeyringAccessRequest *request = ask->current_request;
	gboolean app_secret = FALSE;
	gboolean deny = FALSE;
	gboolean iterate = FALSE;

	if(request->item) {
		app_secret = (request->item->type & GNOME_KEYRING_ITEM_APPLICATION_SECRET) == 
					GNOME_KEYRING_ITEM_APPLICATION_SECRET;
	}

	switch (request->request_type) {
	case GNOME_KEYRING_ACCESS_REQUEST_KEYRING:
		if (!launch_ask_helper (ask, ASK_KEYRING_PASSWORD))
			deny = iterate = TRUE;
		break;

	case GNOME_KEYRING_ACCESS_REQUEST_ITEM:
		if (request->item->keyring->locked) {
			if (!launch_ask_helper (ask, ASK_KEYRING_PASSWORD)) 
				deny = iterate = TRUE;

		} else {
			/* We never prompt for simple read requests, they're either allowed or not */
			request->granted = !app_secret;
			deny = app_secret;
			iterate = TRUE;
		}
		break;

	case GNOME_KEYRING_ACCESS_REQUEST_ITEM_SECRET:
		if (request->item->keyring->locked) {
			if (!launch_ask_helper (ask, ASK_KEYRING_PASSWORD)) 
				deny = iterate = TRUE;

		} else if (app_secret) {
			/* We never allow access to 'application' secrets from the wrong app */
			deny = iterate = TRUE;

		} else {
			if (!launch_ask_helper (ask, ASK_ITEM_READ_WRITE_ACCESS)) 
				deny = iterate = TRUE;
		}
		break;

	case GNOME_KEYRING_ACCESS_REQUEST_NEW_KEYRING_PASSWORD:
		if (!launch_ask_helper (ask, ASK_NEW_KEYRING_PASSWORD)) 
			deny = iterate = TRUE;
		break;	

	case GNOME_KEYRING_ACCESS_REQUEST_ORIGINAL_CHANGE_KEYRING_PASSWORD:
		if (!launch_ask_helper (ask, ASK_ORIGINAL_CHANGE_KEYRING_PASSWORD))
			deny = iterate = TRUE;
		break;

	case GNOME_KEYRING_ACCESS_REQUEST_CHANGE_KEYRING_PASSWORD:
		if (!launch_ask_helper (ask, ASK_CHANGE_KEYRING_PASSWORD))
			deny = iterate = TRUE;
		break;

	case GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING:
		if (!launch_ask_helper (ask, ASK_DEFAULT_KEYRING))
			deny = iterate = TRUE;
		break;

	default:
		g_assert_not_reached ();
	}

	if (deny) {
		ask->access_requests = g_list_remove (ask->access_requests, request);
		gnome_keyring_access_request_free (request);
	}

	if (iterate) 
		gnome_keyring_ask_iterate (ask);

}

static gboolean
idle_ask_iterate (gpointer data)
{
	gnome_keyring_ask_iterate ((GnomeKeyringAsk *)data);
	return FALSE;
}

static gboolean
gnome_keyring_ask_iterate (GnomeKeyringAsk *ask)
{
	GnomeKeyringAccessRequest *unfulfilled_request;
	GnomeKeyringAccessRequest *request;
	gboolean currently_asking;
	GList *l;

 restart:
	
	ask->current_request = NULL;
	
	unfulfilled_request = NULL;
	for (l = ask->access_requests; l != NULL; l = l->next) {
		request = l->data;

		if (!request_allowed_for_app (request, ask->app_ref, ask->denied_keyrings, &currently_asking)) {
			if (currently_asking) {
				/* Sleep until dialog is hopefully finished and try again */
				g_timeout_add (400, idle_ask_iterate, ask);
				return FALSE;
			}
			unfulfilled_request = request;
			break;
		}
	}

	if (unfulfilled_request != NULL) {
		if (have_display) {
			ask->current_request = unfulfilled_request;

			schedule_ask (ask);
		} else {
			/* no way to allow request, denying */
			ask->access_requests = g_list_remove (ask->access_requests, unfulfilled_request);
			gnome_keyring_access_request_free (unfulfilled_request);
			goto restart;
		}
		
		return FALSE;
	} else {
		ask->callback (ask->access_requests, ask->callback_data);
		gnome_keyring_ask_free (ask);
		return TRUE;
	}
}

gpointer
gnome_keyring_ask (GList                             *access_requests,
		   GnomeKeyringApplicationRef        *app_ref,
		   GnomeKeyringRequestAccessCallback  callback,
		   gpointer                           data)
{
	GnomeKeyringAsk *ask;

	ask = g_new0 (GnomeKeyringAsk, 1);
	
	ask->buffer = g_string_new (NULL);
	ask->app_ref = app_ref;
	ask->access_requests = gnome_keyring_access_request_list_copy (access_requests);
	ask->callback = callback;
	ask->callback_data = data;

	outstanding_asks = g_list_prepend (outstanding_asks, ask);
	
	if (gnome_keyring_ask_iterate (ask)) {
		/* Already finished & freed */
		return NULL;
	}
	
	return ask;
}


void
gnome_keyring_cancel_ask (gpointer operation)
{
	GnomeKeyringAsk *ask;

	ask = operation;

	gnome_keyring_ask_free (ask);
}

static void
fixup_for_removed (gpointer keyring, gpointer item, gpointer unused)
{
	GList *l, *reql;
	GnomeKeyringAsk *ask;
	GnomeKeyringAccessRequest *request;

	gnome_keyring_client_fixup_for_removed (keyring, item);
	
	for (l = outstanding_asks; l != NULL; l = l->next) {
		ask = l->data;

		/* Note that current_request could be NULL here for an
		 * outstanding request. This happens if e.g. a delete_item
		 * call is what freed the item, since the actual ask
		 * for the delete which has been ok:d is still alive */
		
		reql = ask->access_requests;
		while (reql != NULL) {
			request = reql->data;
			reql = reql->next;

			if ((keyring != NULL && request->keyring == keyring) ||
			    (item != NULL && request->item == item)) {
				if (request == ask->current_request) {
					ask->current_request = NULL;
					/* killing current req */
					gnome_keyring_ask_kill (ask);
					g_idle_add (idle_ask_iterate, ask);
				}
				ask->access_requests = g_list_remove (ask->access_requests,
								      request);
				gnome_keyring_access_request_free (request);
			}
		}
	}
}

GnomeKeyringOperationImplementation keyring_ops[] = {
	{ NULL,  op_lock_all_execute }, /* LOCK_ALL */
	{ NULL, op_set_default_keyring_execute}, /* SET_DEFAULT_KEYRING */
	{ NULL, op_get_default_keyring_execute}, /* GET_DEFAULT_KEYRING */
	{ NULL, op_list_keyrings_execute}, /* LIST_KEYRINGS */
	{ op_create_keyring_collect, op_create_keyring_execute}, /* CREATE_KEYRING */
	{ NULL, op_lock_keyring_execute}, /* LOCK_KEYRING */
	{ NULL, op_unlock_keyring_execute}, /* UNLOCK_KEYRING */
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

static RETSIGTYPE
cleanup_handler (int sig)
{
        cleanup_socket_dir ();
        _exit (2);
}

static int
sane_dup2 (int fd1, int fd2)
{
	int ret;

 retry:
	ret = dup2 (fd1, fd2);
	if (ret < 0 && errno == EINTR)
		goto retry;
	
	return ret;
}

static void
close_stdinout (void)
{
	int fd;
	
	fd = open ("/dev/null", O_RDONLY);
	sane_dup2 (fd, 0);
	close (fd);
	
	fd = open ("/dev/null", O_WRONLY);
	sane_dup2 (fd, 1);
	close (fd);
}

static gboolean
lifetime_slave_pipe_io (GIOChannel  *channel,
			GIOCondition cond,
			gpointer     callback_data)
{
        cleanup_socket_dir ();
        _exit (2);
}

int
main (int argc, char *argv[])
{
	const char *path;
	char *fd_str;
	int fd;
	pid_t pid;
	gboolean foreground;
	gboolean daemon;
	GIOChannel *channel;
	int i;
	
	g_type_init ();

	/* We do not use gcrypt in a multi-threaded manner */
	gcry_check_version (LIBGCRYPT_VERSION);
	
	if (!create_master_socket (&path)) {
		exit (1);
	}

	srand (time (NULL));
	
	if (g_getenv ("DISPLAY") != NULL) {
		have_display = TRUE;
	}

	foreground = FALSE;
	daemon = FALSE;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (strcmp (argv[i], "-f") == 0) {
				foreground = TRUE;
			}
			if (strcmp (argv[i], "-d") == 0) {
				daemon = TRUE;
			}
		}
	}

	if (!foreground) {
		pid = fork ();
		if (pid == 0) {
			/* intermediated child */
			if (daemon) {
				pid = fork ();
				
				if (pid != 0) {
					/* still intermediated child */
					
					/* This process exits, so that the
					 * final child will inherit init as parent
					 * to avoid zombies
					 */
					if (pid == -1) {
						exit (1);
					} else {
						/* This is where we know the pid of the daemon.
						 * The initial process will waitpid until we exit,
						 * so there is no race */
						g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
						g_print ("GNOME_KEYRING_PID=%d\n", (gint)pid);
						exit (0);
					}
				}
			}
			
			close_stdinout ();
			
			/* final child continues here */
		} else {
			if (daemon) {
				int status;
				/* Initial process, waits for intermediate child */
				if (pid == -1) {
					exit (1);
				}
				waitpid (pid, &status, 0);
				if (status != 0) {
					exit (status);
				}
			} else {
				g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
				g_print ("GNOME_KEYRING_PID=%d\n", (gint)pid);
			}
			
			exit (0);
		}
	} else {
		g_print ("GNOME_KEYRING_SOCKET=%s\n", path);
		g_print ("GNOME_KEYRING_PID=%d\n", (gint)getpid ());
	}

	/* Daemon process continues here */

	signal (SIGPIPE, SIG_IGN);
	signal (SIGINT, cleanup_handler);
        signal (SIGHUP, cleanup_handler);
        signal (SIGTERM, cleanup_handler);
	
	session_keyring = gkr_keyring_new ("session", NULL);
	gkr_daemon_add_keyring (session_keyring);

	default_keyring = NULL;
	update_keyrings_from_disk ();

	loop = g_main_loop_new (NULL, FALSE);

	fd_str = getenv ("GNOME_KEYRING_LIFETIME_FD");
	if (fd_str != NULL && fd_str[0] != 0) {
		fd = atoi (fd_str);
		if (fd != 0) {
			channel = g_io_channel_unix_new (fd);
			g_io_add_watch (channel,
					G_IO_IN | G_IO_HUP,
					lifetime_slave_pipe_io, NULL);
			g_io_channel_unref (channel);
		}
		
	}
	
#ifdef WITH_DBUS
	gnome_keyring_daemon_dbus_setup (loop, path);
#endif
	
	g_main_loop_run (loop);

#ifdef WITH_DBUS
	gnome_keyring_daemon_dbus_cleanup ();
#endif
	
	cleanup_socket_dir ();
	return 0;
}

