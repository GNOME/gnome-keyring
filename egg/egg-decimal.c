/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg-decimal.h"

#include <string.h>

gpointer
egg_decimal_decode (const gchar *data,
                    gssize n_data,
                    gsize *n_decoded)
{
	gboolean saw_non_zero = FALSE;
	guint8 *digits = NULL;
	guint n_digits = 0;
	guchar *usg;
	gchar ch;
	guint carry;
	guint i;
	guint cleared;
	guchar *at_byte;
	guint at_bit;
	gsize length;

	g_return_val_if_fail (data, NULL);

	if (n_data < 0)
		n_data = strlen (data);

	/* Convert everything to an array of digits */
	digits = g_new0 (guint8, n_data);
	for (i = 0; i < n_data; i++) {
		ch = data[i];
		if (ch < '0' || ch > '9') {
			g_free (digits);
			return NULL;
		} else if (ch != '0' || saw_non_zero) {
			digits[n_digits] = ch - '0';
			n_digits++;
			saw_non_zero = TRUE;
		}
	}

	usg = g_new0 (guchar, n_data);
	cleared = 0;
	at_byte = usg + n_data - 1;
	at_bit = 0;

	/* for every digit ... */
	while (cleared < n_digits) {
		/* ... store the bit depending on whether last digit is odd */
		guchar bit = (digits[n_digits - 1] % 2);
		*at_byte |= (bit << at_bit);
		if (at_bit++ == 7) {
			at_bit = 0;
			at_byte--;
			g_assert (at_byte >= usg);
		}

		/* ... divide digits by two */
		carry = 0;
		for (i = cleared; i < n_digits; i++) {
			gboolean odd = (digits[i] % 2);
			digits[i] = digits[i] / 2 + carry;
			carry = odd ? 5 : 0;
			if (i == cleared && digits[i] == 0)
				cleared++;
		}
	}

	if (at_bit == 0)
		at_byte++;

	length = n_data - (at_byte - usg);
	memmove (usg, at_byte, length);
	if (n_decoded)
		*n_decoded = length;
	return usg;
}
