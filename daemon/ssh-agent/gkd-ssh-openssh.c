
#include "gkd-ssh-openssh.h"

#include <string.h>

GBytes *
gkd_ssh_openssh_parse_public_key (GBytes *input,
                                  gchar **comment)
{
	const guchar *at;
	guchar *decoded;
	gsize n_decoded;
	gint state;
	guint save;
	const guchar *data;
	gsize n_data;

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

	/* Find the first space */
	at = memchr (data, ' ', n_data);
	if (!at) {
		g_message ("SSH public key missing space");
		return NULL;
	}

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

	/* Decode the base64 key */
	save = state = 0;
	decoded = g_malloc (n_data * 3 / 4);
	n_decoded = g_base64_decode_step ((gchar*)data, n_data, decoded, &state, &save);

	if (!n_decoded) {
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
		*comment = n_data ? g_strndup ((gchar*)data, n_data) : NULL;

	return g_bytes_new_take (decoded, n_decoded);
}
