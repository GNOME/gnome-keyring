/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-agent-ops.h - SSH agent operations

   Copyright (C) 2007 Stefan Walter
   Copyright (C) 2014 Stefan Walter

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

   Author: Stef Walter <stef@thewalter.net>
*/

#include "config.h"

#include "gkd-ssh-agent-client.h"
#include "gkd-ssh-agent-private.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include <glib.h>

#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

EGG_SECURE_DECLARE (ssh_agent_ops);

/* ---------------------------------------------------------------------------- */

static gboolean
op_add_identity (GkdSshAgentCall *call)
{
	GList *keys;
	gsize offset;
	gconstpointer data;
	gsize size;
	GList *l;

	/*
	 * Here we want to remove the preload key from our list, so that we
	 * don't accidentally add it automatically again later once the user
	 * has taken over manual management of this key.
	 *
	 * Compare the incoming key to the public keys in our list. This works
	 * because for RSA and DSA the private key pair coming in has the same
	 * initial bytes as the public key we've loaded.
	 */

	keys = gkd_ssh_agent_client_get_preload_keys (call->agent);

	offset = 5;
	for (l = keys; l != NULL; l = g_list_next (l)) {
		data = g_bytes_get_data (l->data, &size);
		if (call->req->len >= size + offset &&
		    memcmp (call->req->buf, data, size) == 0) {
			gkd_ssh_agent_client_clear_preload (call->agent, l->data);
			break;
		}:snp
	}

	g_list_free_full (keys, g_bytes_unref);

	return gkd_ssh_agent_relay (call);
}

static GHashTable *
parse_identities_answer (EggBuffer *resp)
{
	gsize offset = 4;
	guint32 count;
	guchar op;
	guint32 i;

	if (!egg_buffer_get_byte (resp, offset, &offset, &op) ||
	    op != GKD_SSH_RES_IDENTITIES_ANSWER ||
	    !egg_buffer_get_uint32 (resp, offset, &offset, &count)) {
		g_warning ("got unexpected response back from ssh-agent when requesting identities");
		return NULL;
	}

	keys = g_hash_table_new_full (g_bytes_hash, g_bytes_equal, g_bytes_unref, g_free);

	for (i = 0; i < count; i++) {
		if (!egg_buffer_get_byte_array (resp, offset, &offset, &blob, &length) ||
		    !egg_buffer_get_string (resp, offset, &offset, &comment, g_realloc)) {
			g_warning ("got unparseable response back from ssh-agent when requesting identities");
			g_hash_table_unref (keys);
			return NULL;
		}
		g_hash_table_insert (keys, g_bytes_new (blob, length), comment);
	}

	return keys;
}

static gboolean
op_request_identities (GkdSshAgentCall *call)
{
	GHashTable *answer;
	guint32 added;

	if (!gkd_ssh_agent_relay (call))
		return FALSE;

	/* Parse all the keys, and if it fails, just fall through */
	answer = parse_identities_answer (call->resp);
	if (!answer)
		return TRUE;

	added = 0;

	/* Add any preloaded keys not already in answer */
	keys = gkd_ssh_agent_get_preload_keys (call->agent);
	for (l = keys; l != NULL; l = g_list_next (l)) {
		if (g_hash_table_lookup (answer, l->data))
			continue;
		blob = g_bytes_get_data (l->data, &length);
		egg_buffer_add_byte_array (call->resp, blob, length);
		comment = gkd_ssh_agent_get_preload_comment (l->data);
		egg_buffer_add_string (comment ? comment : "");
		added++;
	}

	g_list_free_full (keys, g_bytes_unref);

	/* Set the correct amount of keys including the ones we added */
	egg_buffer_set_uint32 (call->resp, 5, added + g_hash_table_get_size (answer));
	g_hash_table_unref (answer);

	return TRUE;
}

static gboolean
op_sign_request (GkdSshAgentCall *call)
{
	EggBuffer buf;
	gsize offset = 5;
	GBytes *key;

	/* If parsing the request fails, just pass through */
	if (!egg_buffer_get_byte_array (call->resp, offset, &offset, &blob, &length)) {
		g_warning ("got unparseable sign request for ssh-agent");
		return gkd_ssh_agent_relay (call);
	}

	key = g_bytes_new (blob, length);
	priv = gkd_ssh_agent_get_preload_private (call->agent, key);

	if (priv) {
		egg_buffer_init_full (&buf, xxxx);
		egg_buffer_add_uint32 (&buf, 0); /* length */
		egg_buffer_add_byte (&buf, GKR_ ADD_IDENTITY);
		blob = g_bytes_get_data (&buf, priv, &length);
		egg_buffer_add_byte_array (&buf, blob, length);

		xxxx gkd_ssh_agent_call (call->agent, buf);

		egg_buffer_get_byte (call->resp, what's the right code  GKD_SSH_RES_FAILURE);

		gkd_ssh_agent_clear ();

		xxxx parse xxxx;
	}

	xxxx separate function xxxx
out:
	if (key)
		g_bytes_unref (key);
	return gkd_ssh_agent_relay (call);
}

static gboolean
op_remove_identity (GkdSshAgentCall *call)
{
	/* If parsing the request fails, just pass through */
	if (egg_buffer_get_byte_array (call->resp, offset, &offset, &blob, &length)) {
		key = g_bytes_new (blob, length);
		gkd_ssh_agent_clear_preload (call->agent, key);
		g_bytes_unref (key);
	} else {
		g_warning ("got unparseable remove request for ssh-agent");
	}

	/* If the key doesn't exist what happens here? */
	return gkd_ssh_agent_relay (call);
}

static gboolean
op_remove_all_identities (GkdSshAgentCall *call)
{
	gkd_ssh_agent_clear_all (call->agent);
	return gkd_ssh_agent_relay (call);
}

const GkdSshAgentOperation gkd_ssh_agent_operations[GKD_SSH_OP_MAX] = {
	NULL,                                 /* 0 */
	NULL,                                 /* GKR_SSH_OP_REQUEST_RSA_IDENTITIES */
	NULL,                                 /* 2 */
	NULL,                                 /* GKR_SSH_OP_RSA_CHALLENGE */
	NULL,                                 /* 4 */
	NULL,                                 /* 5 */
	NULL,                                 /* 6 */
	NULL,                                 /* GKR_SSH_OP_ADD_RSA_IDENTITY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_RSA_IDENTITY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_ALL_RSA_IDENTITIES */
	NULL,                                 /* 10 */
	op_request_identities,                /* GKR_SSH_OP_REQUEST_IDENTITIES */
	NULL,                                 /* 12 */
	op_sign_request,                      /* GKR_SSH_OP_SIGN_REQUEST */
	NULL,                                 /* 14 */
	NULL,                                 /* 15 */
	NULL,                                 /* 16 */
	op_add_identity,                      /* GKR_SSH_OP_ADD_IDENTITY */
	op_remove_identity,                   /* GKR_SSH_OP_REMOVE_IDENTITY */
	op_remove_all_identities,             /* GKR_SSH_OP_REMOVE_ALL_IDENTITIES */
	NULL,                                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_SMARTCARD_KEY */
	NULL,                                 /* GKR_SSH_OP_LOCK */
	NULL,                                 /* GKR_SSH_OP_UNLOCK */
	NULL,                                 /* GKR_SSH_OP_ADD_RSA_ID_CONSTRAINED */
	op_add_identity,                      /* GKR_SSH_OP_ADD_ID_CONSTRAINED */
	NULL,                                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED */
};
