/*
 * gnome-keyring
 *
 * Copyright (C) 2014 Stef Walter
 * Copyright (C) 2018 Red Hat, Inc.
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
 *
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno
 */

#include "config.h"

#include <string.h>

#include "gkd-ssh-agent-util.h"

gboolean
_gkd_ssh_agent_read_packet (GSocketConnection *connection,
			    EggBuffer *buffer,
			    GCancellable *cancellable,
			    GError **error)
{
	GInputStream *stream;
	guint32 packet_size;
	gsize bytes_read;

	stream = g_io_stream_get_input_stream (G_IO_STREAM (connection));

	egg_buffer_reset (buffer);
	egg_buffer_resize (buffer, 4);

	if (!g_input_stream_read_all (stream, buffer->buf, 4, &bytes_read, cancellable, error))
		return FALSE;

	if (bytes_read < 4) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
			     "connection closed by peer");
		return FALSE;
	}

	if (!egg_buffer_get_uint32 (buffer, 0, NULL, &packet_size) ||
	    packet_size < 1) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			     "invalid packet size %u",
			     packet_size);
		return FALSE;
	}

	egg_buffer_resize (buffer, packet_size + 4);
	if (!g_input_stream_read_all (stream, buffer->buf + 4, packet_size, &bytes_read, cancellable, error))
		return FALSE;

	return TRUE;
}

gboolean
_gkd_ssh_agent_write_packet (GSocketConnection *connection,
			     EggBuffer *buffer,
			     GCancellable *cancellable,
			     GError **error)
{
	GOutputStream *stream;
	gsize bytes_written;

	stream = g_io_stream_get_output_stream (G_IO_STREAM (connection));
	if (!egg_buffer_set_uint32 (buffer, 0, buffer->len - 4)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			     "cannot read packet length");
		return FALSE;
	}
	return g_output_stream_write_all (stream, buffer->buf, buffer->len, &bytes_written, cancellable, error);
}

gboolean
_gkd_ssh_agent_call (GSocketConnection *connection,
		     EggBuffer*req,
		     EggBuffer *resp,
		     GCancellable *cancellable,
		     GError **error)
{
	return _gkd_ssh_agent_write_packet (connection, req, cancellable, error) &&
		_gkd_ssh_agent_read_packet (connection, resp, cancellable, error);
}

GBytes *
_gkd_ssh_agent_parse_public_key (GBytes *input,
				 gchar **comment)
{
	const guchar *at;
	guchar *decoded;
	gsize n_decoded;
	gint state;
	guint save;
	const guchar *data;
	gsize n_data;
	const guchar *keytype;
	gsize n_keytype;

	g_return_val_if_fail (input, NULL);

	data = g_bytes_get_data (input, &n_data);

	/* Look for a key line */
	for (;;) {
		/* Eat space at the front */
		while (n_data > 0 && g_ascii_isspace (data[0])) {
			++data;
			--n_data;
		}

		/* Not a comment or blank line? Then parse... */
		if (data[0] != '#')
			break;

		/* Skip to the next line */
		at = memchr (data, '\n', n_data);
		if (!at)
			return NULL;
		at += 1;
		n_data -= (at - data);
		data = at;
	}

	/* Limit to use only the first line */
	at = memchr (data, '\n', n_data);
	if (at != NULL)
		n_data = at - data;

	keytype = data;

	/* Find the first space */
	at = memchr (data, ' ', n_data);
	if (!at) {
		g_message ("SSH public key missing space");
		return NULL;
	}

	n_keytype = at - data;

	/* Skip more whitespace */
	n_data -= (at - data);
	data = at;
	while (n_data > 0 && (data[0] == ' ' || data[0] == '\t')) {
		++data;
		--n_data;
	}

	/* Find the next whitespace, or the end */
	at = memchr (data, ' ', n_data);
	if (at == NULL)
		at = data + n_data;

	/* Check if the chunk is the base64 key */
	if ((at - data) % 4 != 0) {
		g_message ("SSH public key missing key data");
		return NULL;
	}

	/* Decode the base64 key */
	save = state = 0;
	decoded = g_malloc (n_data * 3 / 4);
	n_decoded = g_base64_decode_step ((gchar*)data, at - data, decoded, &state, &save);

	if (!n_decoded) {
		g_free (decoded);
		return NULL;
	}

	/* Check if the key type is prefixed to the decoded blob */
	if (!(n_decoded > n_keytype + 4 &&
	      egg_buffer_decode_uint32 (decoded) == n_keytype &&
	      memcmp (keytype, decoded + 4, n_keytype) == 0)) {
		g_message ("SSH public key missing key type");
		g_free (decoded);
		return NULL;
	}

	/* Skip more whitespace */
	n_data -= (at - data);
	data = at;
	while (n_data > 0 && (data[0] == ' ' || data[0] == '\t')) {
		++data;
		--n_data;
	}

	/* If there's data left, its the comment */
	if (comment)
		*comment = n_data ? g_strndup ((gchar*)data, n_data) : g_strdup ("");

	return g_bytes_new_take (decoded, n_decoded);
}

gchar *
_gkd_ssh_agent_canon_error (gchar *str)
{
	gchar *start = str;
	gchar *end = str + strlen (str) + 1;

	for (;;) {
		start = strchr (start, '\r');
		if (!start)
			break;
		memmove (start, start + 1, end - (start + 1));
	}

	return str;
}
