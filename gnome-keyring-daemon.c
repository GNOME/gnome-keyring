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
#include "md5.h"

#ifndef HAVE_SOCKLEN_T
#define socklen_t int
#endif

enum AskType {
	ASK_KEYRING_PASSWORD,
	ASK_ITEM_READ_WRITE_ACCESS,
	ASK_NEW_KEYRING_PASSWORD,
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

GnomeKeyring *session_keyring;
GnomeKeyring *default_keyring;

static GMainLoop *loop = NULL;

static gboolean gnome_keyring_ask_iterate (GnomeKeyringAsk *ask);
static void gnome_keyring_fixup_for_deleted (GnomeKeyring *keyring, GnomeKeyringItem *item);

void
gnome_keyring_free (GnomeKeyring *keyring)
{
	GList *l;
	GnomeKeyringItem *item;

	l = keyring->items;
	while (l != NULL) {
		item = l->data;
		l = l->next;

		gnome_keyring_item_free (item);
	}
	g_list_free (keyring->items);
		
	gnome_keyring_fixup_for_deleted (keyring, NULL);

	if (keyring == default_keyring) {
		default_keyring = NULL;
	}

	keyrings = g_list_remove (keyrings, keyring);
	
	g_free (keyring->keyring_name);
	g_free (keyring->file);
	gnome_keyring_free_password (keyring->password);
	g_free (keyring);
}

static void
init_salt (guchar salt[8])
{
	gboolean got_random;
	int i;

	got_random = FALSE;
#ifdef __linux__
	{
		int fd;

		fd = open ("/dev/random", O_RDONLY);
		if (fd != -1) {
			if (read (fd, salt, 8) == 8) {
				got_random = TRUE;
			}
			close (fd);
		}
		
	}
#endif
	if (!got_random) {
		for (i=0; i < 8; i++) {
			salt[i] = (int) (256.0*rand()/(RAND_MAX+1.0));
		}
	}
	
}

GnomeKeyring *
gnome_keyring_new (const char *name, const char *path)
{
	GnomeKeyring *keyring;

	keyring = g_new0 (GnomeKeyring, 1);

	keyring->keyring_name = g_strdup (name);
	keyring->file = g_strdup (path);
     
	keyring->ctime = keyring->mtime = time (NULL);

	/* Default values: */
	keyring->lock_on_idle = FALSE;
	keyring->lock_timeout = 0;

	keyring->hash_iterations = 1000 + (int) (1000.0*rand()/(RAND_MAX+1.0));
	init_salt (keyring->salt);
		
	keyrings = g_list_prepend (keyrings, keyring);
	
	return keyring;
}

static guint32
gnome_keyring_get_new_id (GnomeKeyring *keyring)
{
	GList *l;
	GnomeKeyringItem *item;
	guint32 max;

	max = 0;
	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;

		if (item->id >= max) {
			max = item->id;
		}
	}
	/* Naive unique id lookup, but avoid rollaround at lest: */
	
	if (max == 0xffffffff) {
		return 0;
	}
	return max + 1;
}


GnomeKeyringItem *
gnome_keyring_item_new (GnomeKeyring *keyring,
			GnomeKeyringItemType type)
{
	GnomeKeyringItem *item;
	guint32 id;

	g_assert (!keyring->locked);
	
	id = gnome_keyring_get_new_id (keyring);
	if (id == 0) {
		return NULL;
	}
	
	item = g_new0 (GnomeKeyringItem, 1);
	item->keyring = keyring;
	item->id = id;
	item->locked = keyring->locked;
	item->ctime = item->mtime = time (NULL);
	item->type = type;
		
	keyring->items = g_list_append (keyring->items, item);
	
	return item;
}


void
gnome_keyring_item_free (GnomeKeyringItem *item)
{
	GnomeKeyring *keyring;
	
	gnome_keyring_fixup_for_deleted (NULL, item);
	
	keyring = item->keyring;
	keyring->items = g_list_remove (keyring->items, item);

	gnome_keyring_attribute_list_free (item->attributes);
	if (item->acl != NULL) {
		gnome_keyring_acl_free (item->acl);
	}
	gnome_keyring_free_password (item->display_name);
	gnome_keyring_free_password (item->secret);
	g_free  (item);
}



void
gnome_keyring_access_request_free (GnomeKeyringAccessRequest *access_request)
{
	g_free (access_request->new_keyring);
	gnome_keyring_free_password (access_request->password);
	g_free (access_request);
}

GnomeKeyringAccessRequest *
gnome_keyring_access_request_copy (GnomeKeyringAccessRequest *access_request)
{
	GnomeKeyringAccessRequest *ret;
	
	ret = g_new (GnomeKeyringAccessRequest, 1);
	
	/* shallow copy, we don't own the items/keyrings */
	*ret = *access_request;

	ret->password = g_strdup (ret->password);
	ret->new_keyring = g_strdup (ret->new_keyring);
	
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

static char *
hash_string (const char *str)
{
        guchar digest[16];
	
	gnome_keyring_md5_string (str, digest);
	return gnome_keyring_md5_digest_to_ascii (digest);
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

#ifdef __linux__
	{
		char buffer[1024];
		int len;
		char *path;
		
		path = g_strdup_printf ("/proc/%d/exe", pid); 
		len = readlink (path, buffer, sizeof (buffer));
		g_free (path);

		if (len > 0) {
			app_ref->pathname = g_malloc (len + 1);
			memcpy (app_ref->pathname, buffer, len);
			app_ref->pathname[len] = 0;
		}
		
	}
#endif

	return app_ref;
}

void
gnome_keyring_application_ref_free (GnomeKeyringApplicationRef *app_ref)
{
	g_free (app_ref->display_name);
	g_free (app_ref->pathname);
	g_free (app_ref);
}

GnomeKeyringApplicationRef *
gnome_keyring_application_ref_copy (const GnomeKeyringApplicationRef *app)
{
	GnomeKeyringApplicationRef *copy;

	copy = g_new (GnomeKeyringApplicationRef, 1);
	copy->display_name = g_strdup (app->display_name);
	copy->pathname = g_strdup (app->pathname);
	
	return copy;
}

GnomeKeyringAccessControl *
gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
				  GnomeKeyringAccessType types_allowed)
{
	GnomeKeyringAccessControl *ac;
	ac = g_new (GnomeKeyringAccessControl, 1);

	ac->application = gnome_keyring_application_ref_copy (application);
	ac->types_allowed = types_allowed;
	
	return ac;
}

void
gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac)
{
	gnome_keyring_application_ref_free (ac->application);
	g_free (ac);
}

void
gnome_keyring_acl_free (GList *acl)
{
	g_list_foreach (acl, (GFunc)gnome_keyring_access_control_free, NULL);
	g_list_free (acl);
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
add_item_acl (GnomeKeyringItem *item,
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
			 GList *denied_keyrings)
{
	GnomeKeyringAccessControl *ac;
	GList *l;

	if (request->granted) {
		return TRUE;
	}
	
	if (request->keyring != NULL) {
		if (request->keyring->locked) {
			return FALSE;
		}
		/* TODO: verify app ACL vs keyring?? */
		return TRUE;
	} else if (request->item != NULL) {
		if (request->item->locked) {
			return FALSE;
		}
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
	if (ask->input_watch != 0) {
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
match_attributes (GnomeKeyringItem *item,
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
access_request_from_item (GnomeKeyringItem *item,
			  GnomeKeyringAccessType access_type)
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_ITEM;
	access_request->access_type = access_type;
	access_request->item = item;
	return access_request;
}

static GnomeKeyringAccessRequest *
access_request_from_keyring (GnomeKeyring *keyring,
			     GnomeKeyringAccessType access_type)
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_KEYRING;
	access_request->access_type = access_type;
	access_request->keyring = keyring;
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
access_request_default_keyring ()
{
	GnomeKeyringAccessRequest *access_request;
	access_request = g_new0 (GnomeKeyringAccessRequest, 1);
	access_request->request_type = GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING;
	return access_request;
}


GnomeKeyring *
find_keyring (const char *name)
{
	GList *l;
	GnomeKeyring *keyring;

	for (l = keyrings; l != NULL; l = l->next) {
		keyring = l->data;

		if (strcmp (keyring->keyring_name, name) == 0) {
			return keyring;
		}
	}
	
	return NULL;
}

GnomeKeyringItem *
find_item_in_list (GList *list, guint32 id)
{
	GnomeKeyringItem *item;
	
	while (list != NULL) {
		item = list->data;
		if (item->id == id) {
			return item;
		}
		
		list = list->next;
	}
	return NULL;
}

static GnomeKeyringItem *
find_item (GnomeKeyring *keyring, guint32 id)
{
	return find_item_in_list (keyring->items, id);
}

static GnomeKeyringResult
unlock_keyring (GnomeKeyring *keyring, const char *password)
{
	if (!keyring->locked) {
		return GNOME_KEYRING_RESULT_ALREADY_UNLOCKED;
	} else {
		g_assert (keyring->password == NULL);
		
		keyring->password = g_strdup (password);
		if (!update_keyring_from_disk (keyring, TRUE)) {
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

static void
lock_keyring (GnomeKeyring *keyring)
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
	if (!update_keyring_from_disk (keyring, TRUE)) {
		/* Failed to re-read, remove the keyring */
		g_warning ("Couldn't re-read keyring %s\n", keyring->keyring_name);
		gnome_keyring_free (keyring);
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
	GnomeKeyring *keyring;
	
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
	GnomeKeyring *keyring;

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
	GnomeKeyring *keyring;

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
	GnomeKeyring *keyring;
	
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
op_get_keyring_info_execute (GString *packet,
			     GString *result,
			     GnomeKeyringApplicationRef *app_ref,
			     GList *access_requests)
{
	char *keyring_name;
	GnomeKeyring *keyring;
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
	GnomeKeyring *keyring;
	
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

static GnomeKeyring *
create_new_keyring (const char *keyring_name, const char *password)
{
	GnomeKeyring *keyring;
	
	keyring = gnome_keyring_new (keyring_name, NULL);
	if (keyring != NULL) {
		keyring->file = get_default_keyring_file_for_name (keyring_name);
		keyring->locked = FALSE;
		keyring->password = g_strdup (password);
		save_keyring_to_disk (keyring);
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
	GnomeKeyring *keyring;
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
	GnomeKeyring *keyring;
	GnomeKeyringOpCode opcode;
	
	if (!gnome_keyring_proto_decode_op_string_string (packet,
							  &opcode,
							  &keyring_name,
							  &password)) {
		return FALSE;
	}
	g_assert (opcode == GNOME_KEYRING_OP_UNLOCK_KEYRING);
	
	keyring = find_keyring (keyring_name);
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
op_list_items_collect (GString *packet,
			GList **access_requests_out)
{
	char *keyring_name;
	GnomeKeyring *keyring;
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
	GnomeKeyring *keyring;
	char *keyring_name;
	GnomeKeyringOpCode opcode;
	GnomeKeyringItem *item;
	GList *l;
	GnomeKeyringAccessRequest *req;
	
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
			gnome_keyring_proto_add_uint32 (result, g_list_length (keyring->items));
			for (l = keyring->items; l != NULL; l = l->next) {
				item = l->data;
				gnome_keyring_proto_add_uint32 (result, item->id);
			}
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
	GnomeKeyring *keyring;
	GnomeKeyringAttributeList *attributes;
	guint32 type;
	gboolean update_if_exists;
	GnomeKeyringAttributeList *hashed;
	GList *ilist;
	gboolean found_existing;
	GnomeKeyringItem *item;
	GnomeKeyringAccessRequest *access_request;
	
	if (!gnome_keyring_proto_decode_create_item (packet,
						     &keyring_name, NULL,
						     &attributes, NULL, &type,
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
			if (item->type == type &&
			    match_attributes (item, keyring->locked ? hashed : attributes, TRUE)) {
				found_existing = TRUE;
				access_request =
					access_request_from_item (item, GNOME_KEYRING_ACCESS_WRITE);
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
	GnomeKeyringItem *item;
	GnomeKeyring *keyring;
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
						     &type,
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

	if (type >= GNOME_KEYRING_ITEM_LAST_TYPE ||
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
		item = gnome_keyring_item_new (keyring, type);
	}
	if (item == NULL) {
		res = GNOME_KEYRING_RESULT_DENIED;
		goto bail;
	}

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

	save_keyring_to_disk (keyring);

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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
			item = find_item (keyring, item_id);
			if (item != NULL) {
				access_request =
					access_request_from_item (item,
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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

	if (access_request->item->keyring != keyring ||
	    access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gnome_keyring_item_free (item);
	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);
	
	save_keyring_to_disk (keyring);

 out:
	
	g_free (keyring_name);
	return TRUE;
}



static gboolean
op_get_item_info_or_attributes_collect (GString *packet,
					GList **access_requests_out)
{
	char *keyring_name;
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
			item = find_item (keyring, item_id);
			if (item != NULL) {
				access_request =
					access_request_from_item (item,
								  GNOME_KEYRING_ACCESS_READ);
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
	char *keyring_name;
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
	
	gnome_keyring_proto_add_uint32 (result, item->type);
	if (!gnome_keyring_proto_add_utf8_string (result, item->display_name)) {
		return FALSE;
	}
	if (!gnome_keyring_proto_add_utf8_string (result, item->secret)) {
		return FALSE;
	}
	gnome_keyring_proto_add_time (result, keyring->mtime);
	gnome_keyring_proto_add_time (result, keyring->ctime);
	
out:
	
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
op_set_item_info_or_attributes_collect (GString *packet,
					GList **access_requests_out)
{
	char *keyring_name;
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
			item = find_item (keyring, item_id);
			if (item != NULL) {
				access_request =
					access_request_from_item (item,
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
	guint32 item_id, type;
	GnomeKeyringAccessRequest *access_request;
	char *item_name, *secret;
	
	if (!gnome_keyring_proto_decode_set_item_info (packet,
						       &keyring_name,
						       &item_id,
						       &type,
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

	if (access_request->item->keyring != keyring ||
	    access_request->item == NULL ||
	    access_request->item->locked) {
		gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_DENIED);
		goto out;
	}
	item = access_request->item;

	gnome_keyring_proto_add_uint32 (result, GNOME_KEYRING_RESULT_OK);

	if (type != GNOME_KEYRING_ITEM_NO_TYPE) {
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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

	if (access_request->item->keyring != keyring ||
	    access_request->item == NULL ||
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
	GnomeKeyringItem *item;
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
		    item->type == type &&
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
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
			if (item->type == type &&
			    match_attributes (item, keyring->locked ? hashed : attributes, FALSE)) {
				access_request =
				  access_request_from_item (item, GNOME_KEYRING_ACCESS_READ);
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
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;

	ask->input_watch = 0;
	ask->ask_pid = 0;
	
	/* default for failed requests */
	response = GNOME_KEYRING_ASK_RESPONSE_FAILURE;
	str = NULL;

	if (!failed) {
		lines = g_strsplit (ask->buffer->str, "\n", 3);
		response = atol (lines[0]);
		str = g_strdup (lines[1]);
		g_strfreev (lines);
	}

	if (response == GNOME_KEYRING_ASK_RESPONSE_FAILURE ||
	    response == GNOME_KEYRING_ASK_RESPONSE_DENY) {
			ask->access_requests = g_list_remove (ask->access_requests, ask->current_request);
			gnome_keyring_access_request_free (ask->current_request);
	} else {
		
		switch (ask->current_ask_type) {
		case ASK_DEFAULT_KEYRING:
			if (strlen (str) > 0) {
				keyring = create_new_keyring ("default", str);
				if (keyring != NULL) {
					default_keyring = keyring;
					/* TODO: store the name of the default keyring */
				}
				ask->current_request->granted = TRUE;
			}
			break;
		case ASK_NEW_KEYRING_PASSWORD:
			if (strlen (str) > 0) {
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
			g_assert (item != NULL);
			if (response == GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER) {
				add_item_acl (item, ask->app_ref,
					      GNOME_KEYRING_ACCESS_READ |
					      GNOME_KEYRING_ACCESS_WRITE |
					      GNOME_KEYRING_ACCESS_REMOVE);
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
	GIOChannel *channel;
	char **envp;
	int i, n;
	int stdout;
	GError *error;
	char *argv[] = {
		BINDIR "/gnome-keyring-ask",
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
	if (request->item != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->item->keyring->keyring_name);
		envp[i++] = g_strdup_printf("ITEM_NAME=%s", request->item->display_name);
	} else if (request->keyring != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->keyring->keyring_name);
	} else  if (request->new_keyring != NULL) {
		envp[i++] = g_strdup_printf("KEYRING_NAME=%s", request->new_keyring);
	}
	
	envp[i++] = NULL;

	error = NULL;
	if (ask_type == ASK_KEYRING_PASSWORD) {
		argv[1] = "-k";
	} else if (ask_type == ASK_NEW_KEYRING_PASSWORD) {
		argv[1] = "-n";
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
				      &stdout,
				      NULL,
				      &error)) {
		channel = g_io_channel_unix_new (stdout);
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
	GnomeKeyringAccessRequest *request;

	request = ask->current_request;
	switch (request->request_type) {
	case GNOME_KEYRING_ACCESS_REQUEST_KEYRING:
		if (!launch_ask_helper (ask, ASK_KEYRING_PASSWORD)) {
			/* no way to allow request, denying */
			ask->access_requests = g_list_remove (ask->access_requests, request);
			gnome_keyring_access_request_free (request);
			/* iterate */
			gnome_keyring_ask_iterate (ask);
		}
		break;
	case GNOME_KEYRING_ACCESS_REQUEST_ITEM:
		if (request->item->keyring->locked) {
			if (!launch_ask_helper (ask, ASK_KEYRING_PASSWORD)) {
				/* no way to allow request, denying */
				ask->access_requests = g_list_remove (ask->access_requests, request);
				gnome_keyring_access_request_free (request);
				/* iterate */
				gnome_keyring_ask_iterate (ask);
			}
		} else {
			if (!launch_ask_helper (ask, ASK_ITEM_READ_WRITE_ACCESS)) {
				/* no way to allow request, denying */
				ask->access_requests = g_list_remove (ask->access_requests, request);
				gnome_keyring_access_request_free (request);
				/* iterate */
				gnome_keyring_ask_iterate (ask);
			}
		}
		break;
	case GNOME_KEYRING_ACCESS_REQUEST_NEW_KEYRING_PASSWORD:
		if (!launch_ask_helper (ask, ASK_NEW_KEYRING_PASSWORD)) {
			/* no way to allow request, denying */
			ask->access_requests = g_list_remove (ask->access_requests, request);
			gnome_keyring_access_request_free (request);
			/* iterate */
			gnome_keyring_ask_iterate (ask);
		}
		break;
	case GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING:
		if (!launch_ask_helper (ask, ASK_DEFAULT_KEYRING)) {
			/* no way to allow request, denying */
			ask->access_requests = g_list_remove (ask->access_requests, request);
			gnome_keyring_access_request_free (request);
			/* iterate */
			gnome_keyring_ask_iterate (ask);
		}
		break;
	default:
		g_assert_not_reached ();
	}
}

static gboolean
gnome_keyring_ask_iterate (GnomeKeyringAsk *ask)
{
	GnomeKeyringAccessRequest *unfulfilled_request;
	GnomeKeyringAccessRequest *request;
	GList *l;

 restart:
	
	ask->current_request = NULL;
	
	unfulfilled_request = NULL;
	for (l = ask->access_requests; l != NULL; l = l->next) {
		request = l->data;

		if (!request_allowed_for_app (request, ask->app_ref, ask->denied_keyrings)) {
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


static gboolean
idle_ask_iterate (gpointer data)
{
	gnome_keyring_ask_iterate ((GnomeKeyringAsk *)data);
	return FALSE;
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
gnome_keyring_fixup_for_deleted (GnomeKeyring *keyring, GnomeKeyringItem *item)
{
	GList *l, *reql;
	GnomeKeyringAsk *ask;
	GnomeKeyringAccessRequest *request;

	gnome_keyring_client_fixup_for_deleted (keyring, item);
	
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
	{ NULL, NULL}, /* DELETE_KEYRING */
	{ NULL, op_get_keyring_info_execute}, /* GET_KEYRING_INFO */
	{ NULL, NULL}, /* SET_KEYRING_INFO */
	{ op_list_items_collect, op_list_items_execute}, /* LIST_ITEMS */
	{ op_find_collect, op_find_execute }, /* FIND */
	{ op_create_item_collect, op_create_item_execute}, /* CREATE_ITEM */
	{ op_delete_item_collect, op_delete_item_execute}, /* DELETE_ITEM */
	{ op_get_item_info_or_attributes_collect, op_get_item_info_execute}, /* GET_ITEM_INFO */
	{ op_set_item_info_or_attributes_collect, op_set_item_info_execute}, /* SET_ITEM_INFO */
	{ op_get_item_info_or_attributes_collect, op_get_item_attributes_execute}, /* GET_ITEM_ATTRIBUTES */
	{ op_set_item_info_or_attributes_collect, op_set_item_attributes_execute}, /* SET_ITEM_ATTRIBUTES */
};

#if 0

gboolean
compare_keyrings (GnomeKeyring *a,
		  GnomeKeyring *b)
{
	GList *la, *lb;
	GnomeKeyringItem *ia, *ib;
	GnomeKeyringAttribute *attribute_a, *attribute_b;
	GnomeKeyringAccessControl *aca, *acb;
	GList *acla, *aclb;
	int i;
	
	g_assert (strcmp (a->password, b->password) == 0);
	g_assert (strcmp (a->keyring_name, b->keyring_name) == 0);
	g_assert (a->ctime == b->ctime);
	g_assert (a->mtime == b->mtime);
	g_assert (a->lock_on_idle == b->lock_on_idle);
	g_assert (a->lock_timeout == b->lock_timeout);

	la = a->items;
	lb = b->items;

	while (la != NULL) {
		g_assert (lb != NULL);
		ia = la->data;
		ib = lb->data;

		g_assert (ia->id == ib->id);
		g_assert (ia->type == ib->type);
		g_assert (ia->locked == FALSE);
		g_assert (ia->locked == ib->locked);
		g_assert (ia->ctime == ib->ctime);
		g_assert (ia->mtime == ib->mtime);
		g_assert ((ia->display_name == NULL && ib->display_name == NULL) ||
			  strcmp (ia->display_name, ib->display_name) == 0);
		g_assert ((ia->secret == NULL && ib->secret == NULL) ||
			  strcmp (ia->secret, ib->secret) == 0);
		g_assert (ia->attributes->len == ib->attributes->len);

		attribute_a = (GnomeKeyringAttribute *)ia->attributes->data;
		attribute_b = (GnomeKeyringAttribute *)ib->attributes->data;
		
		for (i = 0; i < ia->attributes->len; i++) {
			g_assert (strcmp (attribute_a[i].name, attribute_b[i].name) == 0);
			g_assert (attribute_a[i].type == attribute_b[i].type);
			
			if (attribute_a[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
				g_assert (strcmp (attribute_a[i].value.string, attribute_b[i].value.string) == 0);
			} else if (attribute_a[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
				g_assert (attribute_a[i].value.integer == attribute_b[i].value.integer);
			} else {
				g_assert_not_reached ();
			}
		}

		acla = ia->acl;
		aclb = ib->acl;

		while (acla != NULL) {
			g_assert (aclb != NULL);

			aca = acla->data;
			acb = aclb->data;
			
			g_assert (aca->types_allowed == acb->types_allowed);
			g_assert ((aca->application->display_name == NULL && acb->application->display_name == NULL) ||
				  strcmp (aca->application->display_name,
					  acb->application->display_name) == 0);
			g_assert ((aca->application->pathname == NULL && acb->application->pathname == NULL) ||
				  strcmp (aca->application->pathname,
					  acb->application->pathname) == 0);

			acla = acla->next;
			aclb = aclb->next;
		}
		g_assert (aclb == NULL);
		

		la = la->next;
		lb = lb->next;
	}
	g_assert (lb == NULL);
	
	
	
	return TRUE;
}

static void
test_files (void)
{
	GnomeKeyring *keyring;
	GnomeKeyring *keyring2;
	gboolean res;
	GnomeKeyringItem *item;
	GnomeKeyringAttribute attribute;
	GnomeKeyringAccessControl *ac;
	GnomeKeyringApplicationRef *app;
	
	keyring = gnome_keyring_new ("test", "./test.keyring");
	keyring->password = "password";
	
	keyring2 = gnome_keyring_new ("test", "./test.keyring");
	keyring2->password = "password";
	
	item = gnome_keyring_item_new (keyring, GNOME_KEYRING_ITEM_NOTE);
	item->display_name = "top secret item";
	item->secret = "top secret text";

	item->attributes = gnome_keyring_attribute_list_new ();
	
	attribute.name = "string attribute";
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = "some text";
	g_array_append_val (item->attributes, attribute);

	attribute.name = "int attribute";
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attribute.value.integer = 42;
	g_array_append_val (item->attributes, attribute);

	app = gnome_keyring_application_ref_new_from_pid (getpid ());
	ac = gnome_keyring_access_control_new (app,
					       GNOME_KEYRING_ACCESS_READ |
					       GNOME_KEYRING_ACCESS_REMOVE);
	item->acl = g_list_prepend (item->acl, ac);
	app = g_new0 (GnomeKeyringApplicationRef, 1);
	app->pathname = "/usr7bin/app";
	app->display_name = "some app";
	ac = gnome_keyring_access_control_new (app,
					       GNOME_KEYRING_ACCESS_READ |
					       GNOME_KEYRING_ACCESS_WRITE);
	item->acl = g_list_prepend (item->acl, ac);




	item = gnome_keyring_item_new (keyring, GNOME_KEYRING_ITEM_NOTE);
	item->display_name = "top secret item 2";
	item->secret = "top secret text again";

	item->attributes = gnome_keyring_attribute_list_new ();
	
	attribute.name = "string attribute";
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = "some other text";
	g_array_append_val (item->attributes, attribute);

	attribute.name = "int attribute";
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attribute.value.integer = 17;
	g_array_append_val (item->attributes, attribute);

	app = gnome_keyring_application_ref_new_from_pid (getpid ());
	ac = gnome_keyring_access_control_new (app,
					       GNOME_KEYRING_ACCESS_READ |
					       GNOME_KEYRING_ACCESS_REMOVE);
	item->acl = g_list_prepend (item->acl, ac);
	app = g_new0 (GnomeKeyringApplicationRef, 1);
	app->pathname = "/usr7bin/app2";
	app->display_name = "some app2";
	ac = gnome_keyring_access_control_new (app,
					       GNOME_KEYRING_ACCESS_READ |
					       GNOME_KEYRING_ACCESS_WRITE);
	item->acl = g_list_prepend (item->acl, ac);

	
	save_keyring_to_disk (keyring);

	res = update_keyring_from_disk (keyring2, FALSE);
	g_print ("update_keyring_from_disk returned %d\n", res);

	g_print ("keyrings equal: %d\n", compare_keyrings (keyring, keyring2));
}

#endif

static void
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

int
main (int argc, char *argv[])
{
	const char *path;
	pid_t pid;
	gboolean foreground;
	int i;
	
	
	if (!create_master_socket (&path)) {
		exit (1);
	}

	srand (time (NULL));
	
	if (g_getenv ("DISPLAY") != NULL) {
		have_display = TRUE;
	}

	foreground = FALSE;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (strcmp (argv[i], "-f") == 0) {
				foreground = TRUE;
			}
		}
	}

	if (!foreground) {
		pid = fork ();
		if (pid == 0) {
			int fd;
			/* intermediated child */

			/* We have to close the std read/write so the
			 * paren't doesn't hang */
			fd = open ("/dev/null", O_RDONLY);
			close (0);
			sane_dup2 (fd, 0);
			close (fd);
			
			fd = open ("/dev/null", O_WRONLY);
			close (1);
			sane_dup2 (fd, 1);
			close (fd);

			pid = fork ();

			if (pid != 0) {
				/* still intermediated child */
				
				/* This process just exits, so that the
				 * final child will inherit init as parent
				 * to avoid zombies
				 */
				if (pid == -1) {
					exit (1);
				} else {
					exit (0);
				}
			}
			/* final child continues here */
		} else {
			int status;
			/* Initial process, waits for intermediate child */
			if (pid == -1) {
				exit (1);
			}
			waitpid (pid, &status, 0);
			if (status != 0) {
				exit (status);
			}

			g_print ("GNOME_KEYCHAIN_SOCKET=%s\n", path);

			exit (0);
		}
	} else {
		g_print ("GNOME_KEYCHAIN_SOCKET=%s\n", path);
	}

	/* Daemon process continues here */

        if (!foreground) {
                signal (SIGINT, SIG_IGN);
	} else {
		signal (SIGINT, cleanup_handler);
	}
	signal (SIGPIPE, SIG_IGN);
        signal (SIGHUP, cleanup_handler);
        signal (SIGTERM, cleanup_handler);
	
	session_keyring = gnome_keyring_new ("session", NULL);

	default_keyring = NULL;
	update_keyrings_from_disk ();

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);
	
	cleanup_socket_dir ();
	return 0;
}
