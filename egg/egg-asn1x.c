/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1x.c - ASN.1/DER parse and coding routines

   Copyright (C) 2009 Stefan Walter

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

/*
 * Some portions are:
 *
 *      Copyright (C) 2004, 2006, 2008, 2009 Free Software Foundation
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBTASN1.
 *
 * The LIBTASN1 library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "config.h"

#include "egg-asn1x.h"
#include "egg-asn1-defs.h"
#include "egg-timegm.h"

#include <stdlib.h>
#include <string.h>

/* From libtasn1's libtasn.h */

enum {
	ASN1_CLASS_UNIVERSAL = 0x00,
	ASN1_CLASS_APPLICATION = 0x40,
	ASN1_CLASS_CONTEXT_SPECIFIC = 0x80,
	ASN1_CLASS_PRIVATE = 0xC0,
	ASN1_CLASS_STRUCTURED = 0x20,
};

enum {
	ASN1_TAG_BOOLEAN = 0x01,
	ASN1_TAG_INTEGER = 0x02,
	ASN1_TAG_SEQUENCE = 0x10,
	ASN1_TAG_SET = 0x11,
	ASN1_TAG_OCTET_STRING = 0x04,
	ASN1_TAG_BIT_STRING = 0x03,
	ASN1_TAG_UTC_TIME = 0x17,
	ASN1_TAG_GENERALIZED_TIME = 0x18,
	ASN1_TAG_OBJECT_ID = 0x06,
	ASN1_TAG_ENUMERATED = 0x0A,
	ASN1_TAG_NULL = 0x05,
	ASN1_TAG_GENERAL_STRING = 0x1B,
	ASN1_TAG_NUMERIC_STRING = 0x12,
	ASN1_TAG_IA5_STRING = 0x16,
	ASN1_TAG_TELETEX_STRING = 0x14,
	ASN1_TAG_PRINTABLE_STRING = 0x13,
	ASN1_TAG_UNIVERSAL_STRING = 0x1C,
	ASN1_TAG_BMP_STRING = 0x1E,
	ASN1_TAG_UTF8_STRING = 0x0C,
	ASN1_TAG_VISIBLE_STRING = 0x1A,
};

/* From libtasn1's int.h */

enum {
	FLAG_UNIVERSAL = (1<<8),
	FLAG_PRIVATE = (1<<9),
	FLAG_APPLICATION = (1<<10),
	FLAG_EXPLICIT = (1<<11),
	FLAG_IMPLICIT = (1<<12),
	FLAG_TAG = (1<<13),
	FLAG_OPTION = (1<<14),
	FLAG_DEFAULT = (1<<15),
	FLAG_TRUE = (1<<16),
	FLAG_FALSE = (1<<17),
	FLAG_LIST = (1<<18),
	FLAG_MIN_MAX = (1<<19),
	FLAG_1_PARAM = (1<<20),
	FLAG_SIZE = (1<<21),
	FLAG_DEFINED_BY = (1<<22),
	FLAG_GENERALIZED = (1<<23),
	FLAG_UTC = (1<<24),
	FLAG_IMPORTS = (1<<25),
	FLAG_NOT_USED = (1<<26),
	FLAG_SET = (1<<27),
	FLAG_ASSIGN = (1<<28),
	FLAG_DOWN = (1<<29),
	FLAG_RIGHT = (1<<30),
};

typedef struct _Atlv Atlv;
typedef struct _Anode Anode;

struct _Atlv {
	guchar cls;
	gulong tag;
	gint off;
	gint len;

	/* An actual value here */
	GBytes *value;

	/* Reference to what was decoded */
	GBytes *decoded;

	/* Chain this into a tree */
	struct _Atlv *child;
	struct _Atlv *next;

	/* Used during encoding */

	/* Encoding: for bitstring, the number of empty bits at end */
	guint bits_empty : 3;

	/* Encoding: tell us whether we're dealing with a bit string */
	guint prefix_for_bit_string : 1;

	/* Encoding: prefix a zero byte for unsigned integers */
	guint prefix_with_zero_byte : 1;

	/* Encoding: sort children of this tlv (ie: SETOF) */
	guint sorted : 1;
};

struct _Anode {
	const EggAsn1xDef *def;
	const EggAsn1xDef *join;
	GList *opts;

	GBytes *value;
	Atlv *parsed;

	gchar* failure;

	/* If this node was chosen out of a choice */
	guint chosen : 1;

	/* For bitstring the number of empty bits */
	guint bits_empty : 3;

	/* Whether we need to prefix a zero byte to make unsigned */
	guint guarantee_unsigned : 1;
};

/* Forward Declarations */
static gboolean anode_decode_anything (GNode *, Atlv *);
static gboolean anode_decode_one (GNode *, Atlv *);
static GBytes * anode_default_boolean (GNode *node);
static GBytes * anode_default_integer (GNode *node);
static gboolean anode_validate_anything (GNode *, gboolean);
static Atlv * anode_build_anything (GNode*, gboolean want);

static gint
atoin (const char *p, gint digits)
{
	gint ret = 0, base = 1;
	while(--digits >= 0) {
		if (p[digits] < '0' || p[digits] > '9')
			return -1;
		ret += (p[digits] - '0') * base;
		base *= 10;
	}
	return ret;
}

static const guchar *
bytes_get_end (GBytes *data)
{
	const guchar *beg;
	gsize size;
	beg = g_bytes_get_data (data, &size);
	return beg + size;
}

typedef struct {
	EggAllocator allocator;
	gpointer allocated;
} AllocatorClosure;

static void
allocator_closure_free (gpointer data)
{
	AllocatorClosure *closure = data;
	g_assert (closure->allocator);
	(closure->allocator) (closure->allocated, 0);
	g_slice_free (AllocatorClosure, closure);
}

static GBytes *
bytes_new_with_allocator (EggAllocator allocator,
                          guchar **data,
                          gsize length)
{
	AllocatorClosure *closure;

	if (allocator == g_realloc)
		allocator = NULL;

	if (allocator) {
		*data = (allocator) (NULL, length + 1);
		g_return_val_if_fail (*data != NULL, NULL);
		closure = g_slice_new (AllocatorClosure);
		closure->allocated = *data;
		closure->allocator = allocator;
		return g_bytes_new_with_free_func (*data, length,
		                                   allocator_closure_free,
		                                   closure);
	} else {
		*data = g_malloc (length);
		return g_bytes_new_take (*data, length);
	}
}

static GNode*
anode_new (const EggAsn1xDef *def)
{
	Anode *an = g_slice_new0 (Anode);
	an->def = def;
	return g_node_new (an);
}

static gpointer
anode_copy_func (gconstpointer src, gpointer unused)
{
	const Anode *san = src;
	Anode *an = g_slice_new0 (Anode);
	an->def = san->def;
	an->join = san->join;
	an->opts = g_list_copy (san->opts);
	return an;
}

static GNode*
anode_clone (GNode *node)
{
	return g_node_copy_deep (node, anode_copy_func, NULL);
}

static int
anode_def_type (GNode *node)
{
	Anode *an = node->data;
	gint type = an->join ? an->join->type : an->def->type;
	return type & 0xFF;
}

static gboolean
anode_def_type_is_real (GNode *node)
{
	switch (anode_def_type (node)) {
	case EGG_ASN1X_INTEGER:
	case EGG_ASN1X_BOOLEAN:
	case EGG_ASN1X_BIT_STRING:
	case EGG_ASN1X_OCTET_STRING:
	case EGG_ASN1X_OBJECT_ID:
	case EGG_ASN1X_TIME:
	case EGG_ASN1X_UTC_TIME:
	case EGG_ASN1X_GENERALIZED_TIME:
	case EGG_ASN1X_NULL:
	case EGG_ASN1X_ENUMERATED:
	case EGG_ASN1X_GENERAL_STRING:
	case EGG_ASN1X_NUMERIC_STRING:
	case EGG_ASN1X_IA5_STRING:
	case EGG_ASN1X_TELETEX_STRING:
	case EGG_ASN1X_PRINTABLE_STRING:
	case EGG_ASN1X_UNIVERSAL_STRING:
	case EGG_ASN1X_BMP_STRING:
	case EGG_ASN1X_UTF8_STRING:
	case EGG_ASN1X_VISIBLE_STRING:
		return TRUE;
	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SEQUENCE_OF:
	case EGG_ASN1X_ANY:
	case EGG_ASN1X_SET:
	case EGG_ASN1X_SET_OF:
	case EGG_ASN1X_CHOICE:
		return TRUE;
	case EGG_ASN1X_CONSTANT:
	case EGG_ASN1X_IDENTIFIER:
	case EGG_ASN1X_TAG:
	case EGG_ASN1X_DEFAULT:
	case EGG_ASN1X_SIZE:
	case EGG_ASN1X_DEFINITIONS:
	case EGG_ASN1X_IMPORTS:
		return FALSE;
	}

	g_return_val_if_reached (FALSE);
}

static int
anode_def_flags (GNode *node)
{
	Anode *an = node->data;
	gint type = an->def->type;
	if (an->join)
		type |= an->join->type;
	return type & 0xFFFFFF00;
}

static const gchar*
anode_def_name (GNode *node)
{
	Anode *an = node->data;
	return an->def->name;
}

static const gchar*
anode_def_value (GNode *node)
{
	Anode *an = node->data;
	return an->def->value;
}

static gulong
anode_def_value_as_ulong (const EggAsn1xDef *def)
{
	gchar *end = NULL;
	gulong lval;

	g_return_val_if_fail (def->value, G_MAXULONG);
	lval = strtoul (def->value, &end, 10);
	g_return_val_if_fail (end && !end[0], G_MAXULONG);
	return lval;
}

static GNode*
anode_child_with_name (GNode *node, const gchar *name)
{
	GNode *child;

	for (child = node->children; child; child = child->next) {
		if (g_str_equal (name, anode_def_name (child)))
			return child;
	}

	return NULL;
}

static void
anode_opt_add (GNode *node,
               const EggAsn1xDef *def)
{
	Anode *an = node->data;
	an->opts = g_list_append (an->opts, (gpointer)def);
}

static EggAsn1xDef *
anode_opt_lookup (GNode *node,
                  gint type,
                  const gchar *name)
{
	Anode *an = node->data;
	EggAsn1xDef *def;
	GList *l;

	for (l = an->opts; l; l = g_list_next (l)) {
		def = l->data;
		if (name && def->name && !g_str_equal (name, def->name))
			continue;
		if ((def->type & 0xFF) == type)
			return def;
	}

	return NULL;
}

static EggAsn1xDef *
anode_opt_lookup_value (GNode *node,
                        gint type,
                        const gchar *value)
{
	Anode *an = node->data;
	EggAsn1xDef *def;
	GList *l;

	for (l = an->opts; l; l = g_list_next (l)) {
		def = l->data;
		if (value && def->value && !g_str_equal (value, def->value))
			continue;
		if ((def->type & 0xFF) == type)
			return def;
	}

	return NULL;
}

static GList*
anode_opts_lookup (GNode *node, gint type, const gchar *name)
{
	Anode *an = node->data;
	EggAsn1xDef *def;
	GList *l, *res = NULL;

	for (l = an->opts; l; l = g_list_next (l)) {
		def = l->data;
		if (name && def->name && !g_str_equal (name, def->name))
			continue;
		if ((def->type & 0xFF) == type)
			res = g_list_prepend (res, def);
	}

	return g_list_reverse (res);
}

static Atlv *
atlv_new (void)
{
	return g_slice_new0 (Atlv);
}

static void
atlv_free (Atlv *tlv)
{
	if (!tlv)
		return;

	/* Free attached TLVs */
	atlv_free (tlv->child);
	atlv_free (tlv->next);

	/* Free the TLV */
	if (tlv->decoded)
		g_bytes_unref (tlv->decoded);
	if (tlv->value)
		g_bytes_unref (tlv->value);

	g_slice_free (Atlv, tlv);
}

static Atlv *
atlv_dup (Atlv *tlv,
          gboolean siblings)
{
	Atlv *copy;

	if (!tlv)
		return NULL;

	copy = g_slice_new0 (Atlv);
	memcpy (copy, tlv, sizeof (Atlv));

	if (tlv->value != NULL)
		copy->value = g_bytes_ref (tlv->value);
	if (tlv->decoded != NULL)
		copy->decoded = g_bytes_ref (tlv->decoded);

	copy->child = atlv_dup (tlv->child, TRUE);
	if (siblings)
		copy->next = atlv_dup (tlv->next, TRUE);
	else
		copy->next = NULL;

	return copy;
}

static inline GBytes *
anode_get_value (GNode *node)
{
	Anode *an = node->data;
	return an->value;
}

static inline void
anode_clr_value (GNode *node)
{
	Anode *an = node->data;
	if (an->value)
		g_bytes_unref (an->value);
	an->value = NULL;

	atlv_free (an->parsed);
	an->parsed = NULL;
}

static inline void
anode_take_value (GNode *node,
                  GBytes *value)
{
	Anode *an = node->data;
	anode_clr_value (node);
	an->value = value;
}

static inline void
anode_set_value (GNode *node,
                 GBytes *value)
{
	anode_take_value (node, g_bytes_ref (value));
}

static inline Atlv *
anode_get_parsed (GNode *node)
{
	Anode *an = node->data;
	return an->parsed;
}

static gboolean
anode_failure (GNode *node, const gchar *failure)
{
	Anode *an = node->data;
	const gchar *prefix = an->def->name;
	if (!prefix && an->join)
		prefix = an->join->name;
	if (!prefix)
		prefix = an->def->value;
	if (!prefix && an->join)
		prefix = an->join->value;
	if (!prefix)
		prefix = "unknown";

	g_free (an->failure);
	an->failure = g_strdup_printf ("%s: %s", prefix, failure);
	g_debug ("%s %s", prefix, an->failure);
	return FALSE; /* So this can be chained */
}

static const gchar*
anode_failure_get (GNode *node)
{
	Anode *an = node->data;
	return an->failure;
}

static void
anode_clear (GNode *node)
{
	Anode *an = node->data;
	anode_clr_value (node);
	g_free (an->failure);
	an->failure = NULL;
}

static gboolean
anode_free_func (GNode *node, gpointer unused)
{
	Anode *an = node->data;
	anode_clear (node);
	g_list_free (an->opts);
	g_slice_free (Anode, an);
	return FALSE;
}

static void
anode_destroy (GNode *node)
{
	if (!G_NODE_IS_ROOT (node))
		g_node_unlink (node);
	g_node_traverse (node, G_IN_ORDER, G_TRAVERSE_ALL, -1, anode_free_func, NULL);
	g_node_destroy (node);
}

static gulong
anode_calc_tag_for_flags (GNode *node, gint flags)
{
	EggAsn1xDef *def;

	/* A context specific tag */
	if (flags & FLAG_TAG) {
		def = anode_opt_lookup (node, EGG_ASN1X_TAG, NULL);
		g_return_val_if_fail (def, G_MAXULONG);
		return anode_def_value_as_ulong (def);
	}

	/* A tag from the universal set */
	switch (anode_def_type (node)) {
	case EGG_ASN1X_INTEGER:
		return ASN1_TAG_INTEGER;
	case EGG_ASN1X_ENUMERATED:
		return ASN1_TAG_ENUMERATED;
	case EGG_ASN1X_BOOLEAN:
		return ASN1_TAG_BOOLEAN;
	case EGG_ASN1X_BIT_STRING:
		return ASN1_TAG_BIT_STRING;
	case EGG_ASN1X_OCTET_STRING:
		return ASN1_TAG_OCTET_STRING;
	case EGG_ASN1X_OBJECT_ID:
		return ASN1_TAG_OBJECT_ID;
	case EGG_ASN1X_NULL:
		return ASN1_TAG_NULL;
	case EGG_ASN1X_GENERAL_STRING:
		return ASN1_TAG_GENERAL_STRING;
	case EGG_ASN1X_NUMERIC_STRING:
		return ASN1_TAG_NUMERIC_STRING;
	case EGG_ASN1X_IA5_STRING:
		return ASN1_TAG_IA5_STRING;
	case EGG_ASN1X_TELETEX_STRING:
		return ASN1_TAG_TELETEX_STRING;
	case EGG_ASN1X_PRINTABLE_STRING:
		return ASN1_TAG_PRINTABLE_STRING;
	case EGG_ASN1X_UNIVERSAL_STRING:
		return ASN1_TAG_UNIVERSAL_STRING;
	case EGG_ASN1X_BMP_STRING:
		return ASN1_TAG_BMP_STRING;
	case EGG_ASN1X_UTF8_STRING:
		return ASN1_TAG_UTF8_STRING;
	case EGG_ASN1X_VISIBLE_STRING:
		return ASN1_TAG_VISIBLE_STRING;
	case EGG_ASN1X_TIME:
		if (flags & FLAG_GENERALIZED)
			return ASN1_TAG_GENERALIZED_TIME;
		else if (flags & FLAG_UTC)
			return ASN1_TAG_UTC_TIME;
		else
			g_return_val_if_reached (G_MAXULONG);
	case EGG_ASN1X_UTC_TIME:
		return ASN1_TAG_UTC_TIME;
	case EGG_ASN1X_GENERALIZED_TIME:
		return ASN1_TAG_GENERALIZED_TIME;
	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SEQUENCE_OF:
		return ASN1_TAG_SEQUENCE;
	case EGG_ASN1X_SET:
	case EGG_ASN1X_SET_OF:
		return ASN1_TAG_SET;

	/* These should be handled specially */
	case EGG_ASN1X_ANY:
	case EGG_ASN1X_CHOICE:
		return G_MAXULONG;

	/* These are not real nodes */
	case EGG_ASN1X_CONSTANT:
	case EGG_ASN1X_IDENTIFIER:
	case EGG_ASN1X_TAG:
	case EGG_ASN1X_DEFAULT:
	case EGG_ASN1X_SIZE:
	case EGG_ASN1X_DEFINITIONS:
	case EGG_ASN1X_IMPORTS:
		g_return_val_if_reached (G_MAXULONG);
	}

	g_return_val_if_reached (G_MAXULONG);
}

static gulong
anode_calc_tag (GNode *node)
{
	return anode_calc_tag_for_flags (node, anode_def_flags (node));
}

static gboolean
anode_calc_explicit_for_flags (GNode *node,
                               gint flags,
                               guchar *cls_type)
{
	const EggAsn1xDef *opt;
	if ((flags & FLAG_TAG) != FLAG_TAG)
		return FALSE;
	opt = anode_opt_lookup (node, EGG_ASN1X_TAG, NULL);
	g_return_val_if_fail (opt, FALSE);
	if (cls_type) {
		if (opt->type & FLAG_UNIVERSAL)
			*cls_type = ASN1_CLASS_UNIVERSAL;
		else if (opt->type & FLAG_APPLICATION)
			*cls_type = ASN1_CLASS_APPLICATION;
		else if (opt->type & FLAG_PRIVATE)
			*cls_type = ASN1_CLASS_PRIVATE;
		else
			*cls_type = ASN1_CLASS_CONTEXT_SPECIFIC;
	}
	if ((opt->type & FLAG_IMPLICIT) == FLAG_IMPLICIT)
		return FALSE;
	return TRUE;
}

/* -------------------------------------------------------------------------
 * PARSING
 */

static gboolean
atlv_parse_cls_tag (const guchar *at,
                    const guchar *end,
                    guchar *cls,
                    gulong *tag,
                    gint *off)
{
	gint punt, ris, last;
	gint n_data;
	guchar val;

	g_assert (end >= at);
	g_assert (cls != NULL);
	g_assert (off != NULL);

	n_data = end - at;

	if (n_data < 2)
		return FALSE;

	*cls = at[0] & 0xE0;

	/* short form */
	if ((at[0] & 0x1F) != 0x1F) {
		*off = 1;
		ris = at[0] & 0x1F;

	/* Long form */
	} else {
		punt = 1;
		ris = 0;
		while (punt <= n_data) {
			val = at[punt++];
			last = ris;
			ris = ris * 128;

			/* wrapper around, and no bignums... */
			if (ris < last)
				return FALSE;

			last = ris;
			ris += (val & 0x7F);

			/* wrapper around, and no bignums... */
			if (ris < last)
				return FALSE;

			if ((val & 0x7F) == val)
				break;
		}

		if (punt >= n_data)
			return FALSE;

		*off = punt;
	}

	if (tag)
		*tag = ris;

	return TRUE;
}

static gint
atlv_parse_length (const guchar *at,
                   const guchar *end,
                   gint *off)
{
	gint ans;
	gint k, punt;
	gint n_data;

	g_assert (at != NULL);
	g_assert (end != NULL);
	g_assert (end > at);
	g_assert (off != NULL);

	*off = 0;
	n_data = end - at;

	/* short form */
	if (!(at[0] & 128)) {
		*off = 1;
		return at[0];

	/* Long form */
	} else {
		k = at[0] & 0x7F;
		punt = 1;

		/* definite length method */
		if (k) {
			ans = 0;
			while (punt <= k && punt < n_data) {
				/* we wrapped around, no bignum support... */
				if (ans > G_MAXINT / 256)
					return -2;
				ans = ans * 256;

				/* we wrapped around, no bignum support... */
				if (ans > G_MAXINT - at[punt])
					return -2;
				ans += at[punt++];
			}

		/* indefinite length method */
		} else {
			ans = -1;
		}

		*off = punt;
		return ans;
	}
}

static gboolean
atlv_parse_cls_tag_len (const guchar *at,
                        const guchar *end,
                        guchar *cls,
                        gulong *tag,
                        gint *off,
                        gint *len)
{
	gint cb1, cb2;

	g_assert (at != NULL);
	g_assert (end != NULL);
	g_assert (end >= at);
	g_assert (off != NULL);
	g_assert (len != NULL);

	if (!atlv_parse_cls_tag (at, end, cls, tag, &cb1))
		return FALSE;
	*len = atlv_parse_length (at + cb1, end, &cb2);
	if (*len < -1)
		return FALSE;
	*off = cb1 + cb2;
	if (*len >= 0 && at + *off + *len > end)
		return FALSE;
	return TRUE;
}

static const gchar *
atlv_parse_der_tag (guchar cls,
                    gulong tag,
                    gint off,
                    gint len,
                    GBytes *data,
                    const guchar **at,
                    Atlv *tlv)
{
	const guchar *end;
	const gchar *ret;
	const guchar *beg;
	guchar ccls;
	gulong ctag;
	gint clen;
	gint coff;
	Atlv *child;
	Atlv *last;

	g_assert (at != NULL);
	g_assert (tlv != NULL);

	end = bytes_get_end (data);
	g_assert (*at <= end);

	g_return_val_if_fail (*at + off + len <= end, "invalid length of tlv");
	if (len < 0 && !(cls & ASN1_CLASS_STRUCTURED))
		return "indefinite length on non-structured type";

	beg = *at;

	tlv->cls = cls;
	tlv->tag = tag;
	tlv->off = off;
	tlv->len = len;
	(*at) += off;

	/* Structured TLV, with further TLVs inside */
	if (cls & ASN1_CLASS_STRUCTURED) {
		/* If not indefinite length, then calculate end up front */
		if (len >= 0)
			end = (*at) + len;
		last = NULL;
		while (*at < end) {
			if (!atlv_parse_cls_tag_len (*at, end, &ccls, &ctag, &coff, &clen))
				return "content is not encoded properly";

			/* End if indefinite length? */
			if (len < 0 && ccls == ASN1_CLASS_UNIVERSAL && ctag == 0 && clen == 0) {
				(*at) += coff;
				break;
			}

			/* Parse the child */
			child = atlv_new ();
			ret = atlv_parse_der_tag (ccls, ctag, coff, clen, data, at, child);
			if (ret != NULL) {
				atlv_free (child);
				return ret;
			}

			/* Add the child to the right place */
			if (last == NULL)
				tlv->child = child;
			else
				last->next = child;
			last = child;
		}

	/* Non-structured TLV, just a value */
	} else {
		tlv->value = g_bytes_new_with_free_func (*at, len,
		                                         (GDestroyNotify)g_bytes_unref,
		                                         g_bytes_ref (data));
		(*at) += len;
	}

	/* Note the actual DER that we decoded */
	tlv->decoded = g_bytes_new_with_free_func (beg, *at - beg,
	                                           (GDestroyNotify)g_bytes_unref,
	                                           g_bytes_ref (data));

	return NULL; /* Success */
}

static const gchar *
atlv_parse_der (GBytes *data,
                Atlv *tlv)
{
	const guchar *end;
	const guchar *at;
	const gchar *ret;
	guchar cls;
	gulong tag;
	gint off;
	gint len;
	gsize size;

	at = g_bytes_get_data (data, &size);
	g_return_val_if_fail (at != NULL, FALSE);
	end = at + size;

	if (!atlv_parse_cls_tag_len (at, end, &cls, &tag, &off, &len))
		return "content is not encoded properly";

	ret = atlv_parse_der_tag (cls, tag, off, len, data, &at, tlv);
	if (ret != NULL)
		return ret;

	if (at != end)
		return "extra unexpected trailing data";

	return NULL; /* Success */
}

/* -------------------------------------------------------------------------
 * DECODING
 */

static gboolean
anode_decode_choice (GNode *node,
                     Atlv *tlv)
{
	gboolean have = FALSE;
	GNode *child;
	Anode *an;

	for (child = node->children; child; child = child->next) {
		an = (Anode*)child->data;
		if (anode_decode_one (child, tlv)) {
			an->chosen = 1;
			have = TRUE;
		} else {
			an->chosen = 0;
		}
	}

	if (!have)
		return anode_failure (node, "no choice is present");

	return TRUE;
}

static gboolean
anode_decode_sequence_or_set (GNode *node,
                              Atlv *tlv)
{
	Atlv *ctlv;
	gulong tag;
	gint i;

	/*
	 * The reason we can parse a set just like a sequence, is because in DER,
	 * the order of the SET is predefined by the tags. In addition the definitions
	 * we have are sorted.
	 */

	/* Tags must be in ascending order */
	if (anode_def_type (node) == EGG_ASN1X_SET) {
		for (ctlv = tlv->child, i = 0; ctlv != NULL; ctlv = ctlv->next, i++) {
			if (i > 0 && tag > ctlv->tag)
				return anode_failure (node, "content must be in ascending order");
			tag = ctlv->tag;
		}
	}

	return anode_decode_anything (node->children, tlv->child);
}

static gboolean
anode_decode_sequence_or_set_of (GNode *node,
                                 Atlv *tlv)
{
	Atlv *ctlv;
	GNode *child, *other;
	gulong tag;
	gint i;

	/* The first child */
	child = node->children;
	g_return_val_if_fail (child, FALSE);

	for (ctlv = tlv->child, i = 0; ctlv != NULL; ctlv = ctlv->next, i++) {

		/* Tag must have same tag as top */
		if (i == 0)
			tag = anode_calc_tag (child);
		else if (tag != G_MAXULONG && ctlv->tag != tag)
			return anode_failure (node, "invalid mismatched content");

		/* TODO: Set of must be in ascending order in DER encoding */

		if (i == 0) {
			other = child;
		} else {
			other = anode_clone (child);
			g_node_append (node, other);
		}

		if (!anode_decode_one (other, ctlv))
			return FALSE;
	}

	return TRUE;
}

static gboolean
anode_decode_bit_string (GNode *node,
                         Atlv *tlv)
{
	Anode *an = node->data;
	guchar empty, mask;
	GBytes *value;
	const guchar *buf;
	gsize len;

	buf = g_bytes_get_data (tlv->value, &len);
	if (len == 0)
		return anode_failure (node, "invalid length bit string");

	/* The first byte is the number of empty bits */
	empty = buf[0];
	if (empty >= 8)
		return anode_failure (node, "invalid number of empty bits");

	/* Free bits at end must be zero */
	mask = 0xFF >> (8 - empty);
	if (len > 1 && buf[len - 1] & mask)
		return anode_failure (node, "bit string has invalid trailing bits");

	value = g_bytes_new_from_bytes (tlv->value, 1, len - 1);
	anode_take_value (node, value);
	an = node->data;
	an->bits_empty = empty;
	return TRUE;
}

static gboolean
anode_decode_primitive (GNode *node,
                        Atlv *tlv,
                        gint flags)
{
	/* Must not have any tlv children */
	g_assert (tlv->child == NULL);

	switch (anode_def_type (node)) {

	/* Handle bit strings specially */
	case EGG_ASN1X_BIT_STRING:
		return anode_decode_bit_string (node, tlv);

	/* The primitive value types */
	case EGG_ASN1X_INTEGER:
	case EGG_ASN1X_ENUMERATED:
	case EGG_ASN1X_BOOLEAN:
	case EGG_ASN1X_OCTET_STRING:
	case EGG_ASN1X_OBJECT_ID:
	case EGG_ASN1X_NULL:
	case EGG_ASN1X_TIME:
	case EGG_ASN1X_UTC_TIME:
	case EGG_ASN1X_GENERALIZED_TIME:
	case EGG_ASN1X_GENERAL_STRING:
	case EGG_ASN1X_NUMERIC_STRING:
	case EGG_ASN1X_IA5_STRING:
	case EGG_ASN1X_TELETEX_STRING:
	case EGG_ASN1X_PRINTABLE_STRING:
	case EGG_ASN1X_UNIVERSAL_STRING:
	case EGG_ASN1X_BMP_STRING:
	case EGG_ASN1X_UTF8_STRING:
	case EGG_ASN1X_VISIBLE_STRING:
		anode_set_value (node, tlv->value);
		return TRUE;

	/* Just use the 'parsed' which is automatically set */
	case EGG_ASN1X_ANY:
		return TRUE;

	case EGG_ASN1X_CHOICE:
		return anode_decode_choice (node, tlv);
	}

	return anode_failure (node, "primitive value of an unexpected type"); /* UNREACHABLE: tag validation? */
}

static gboolean
anode_decode_structured (GNode *node,
                         Atlv *tlv,
                         gint flags)
{
	switch (anode_def_type (node)) {

	/* Just use the 'parsed' which is automatically set */
	case EGG_ASN1X_ANY:
	case EGG_ASN1X_GENERAL_STRING:
	case EGG_ASN1X_OCTET_STRING:
	case EGG_ASN1X_NUMERIC_STRING:
	case EGG_ASN1X_IA5_STRING:
	case EGG_ASN1X_TELETEX_STRING:
	case EGG_ASN1X_PRINTABLE_STRING:
	case EGG_ASN1X_UNIVERSAL_STRING:
	case EGG_ASN1X_BMP_STRING:
	case EGG_ASN1X_UTF8_STRING:
	case EGG_ASN1X_VISIBLE_STRING:
		return TRUE;

	case EGG_ASN1X_CHOICE:
		return anode_decode_choice (node, tlv);

	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SET:
		return anode_decode_sequence_or_set (node, tlv);

	case EGG_ASN1X_SEQUENCE_OF:
	case EGG_ASN1X_SET_OF:
		return anode_decode_sequence_or_set_of (node, tlv);

	default:
		return anode_failure (node, "structured value of an unexpected type"); /* UNREACHABLE: tag validation? */
	}
}

static gboolean
anode_decode_one_without_tag (GNode *node,
                              Atlv *tlv,
                              gint flags)
{
	gboolean ret;
	Anode *an;

	/* An explicit, wrapped tag */
	if (anode_calc_explicit_for_flags (node, flags, NULL)) {
		if ((tlv->cls & ASN1_CLASS_CONTEXT_SPECIFIC) == 0)
			return anode_failure (node, "missing context specific tag");
		if (tlv->child == NULL)
			return anode_failure (node, "missing context specific child");
		if (tlv->child->next != NULL)
			return anode_failure (node, "multiple context specific children");
		flags &= ~FLAG_TAG;
		ret = anode_decode_one_without_tag (node, tlv->child, flags);

	/* Structured value */
	} else if (tlv->cls & ASN1_CLASS_STRUCTURED) {
		ret = anode_decode_structured (node, tlv, flags);

	/* A primitive simple value */
	} else {
		ret = anode_decode_primitive (node, tlv, flags);
	}

	/* Mark which tlv we used for this node */
	if (ret) {
		an = node->data;
		atlv_free (an->parsed);
		an->parsed = atlv_dup (tlv, FALSE);
	}

	return ret;
}

static gboolean
anode_decode_one (GNode *node,
                  Atlv *tlv)
{
	gint flags = anode_def_flags (node);
	gulong tag;

	tag = anode_calc_tag_for_flags (node, flags);

	/* We don't know what the tag is supposed to be */
	if (tag == G_MAXULONG)
		tag = tlv->tag;

	/* We have no match */
	if (tag != tlv->tag)
		return anode_failure (node, "decoded tag did not match expected");

	return anode_decode_one_without_tag (node, tlv, flags);
}

static gboolean
anode_decode_option_or_default (GNode *node)
{
	gint flags = anode_def_flags (node);

	if (flags & FLAG_OPTION || flags & FLAG_DEFAULT) {
		anode_clr_value (node);
		return TRUE;
	}

	return FALSE;
}

static gboolean
anode_decode_anything (GNode *node,
                       Atlv *tlv)
{
	GNode *prev = NULL;
	GNode *next;
	gulong tag;
	gint flags;

	g_assert (node != NULL);

	while (tlv != NULL) {
		if (node == NULL)
			return anode_failure (prev, "encountered extra tag");

		flags = anode_def_flags (node);
		tag = anode_calc_tag_for_flags (node, flags);

		/* We don't know what the tag is supposed to be */
		if (tag == G_MAXULONG)
			tag = tlv->tag;

		/* We have no match */
		if (tag != tlv->tag) {

			/* See if we can skip this node */
			if (anode_decode_option_or_default (node))
				next = g_node_next_sibling (node);
			else
				next = NULL;

			if (next == NULL)
				return anode_failure (node, "decoded tag did not match expected");

			prev = node;
			node = next;
			continue;
		}

		if (!anode_decode_one_without_tag (node, tlv, flags))
			return FALSE;

		/* Next node and tag */
		prev = node;
		node = g_node_next_sibling (node);
		tlv = tlv->next;
	}

	/* We have no values for these nodes */
	while (node != NULL) {
		if (anode_decode_option_or_default (node))
			node = g_node_next_sibling (node);
		else
			return anode_failure (node, "no decoded value");
	}

	return TRUE;
}

gboolean
egg_asn1x_decode_full (GNode *asn,
                       GBytes *data,
                       gint options)
{
	const gchar *msg;
	gboolean ret;
	Anode *an;
	Atlv *tlv;

	g_return_val_if_fail (asn != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	egg_asn1x_clear (asn);

	tlv = atlv_new ();
	msg = atlv_parse_der (data, tlv);
	if (msg == NULL) {
		ret = anode_decode_anything (asn, tlv);

	/* A failure, set the message manually so it doesn't get a prefix */
	} else {
		an = asn->data;
		g_free (an->failure);
		an->failure = g_strdup (msg);
		ret = FALSE;
	}

	atlv_free (tlv);
	if (ret == FALSE)
		return FALSE;

	return egg_asn1x_validate (asn, !(options & EGG_ASN1X_NO_STRICT));
}

gboolean
egg_asn1x_decode (GNode *asn,
                  GBytes *data)
{
	g_return_val_if_fail (asn != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	return egg_asn1x_decode_full (asn, data, 0);
}

/* -----------------------------------------------------------------------------------
 * UNPARSE
 */

static void
atlv_unparse_len (gulong len,
                  guchar *ans,
                  gint *cb)
{
	guchar temp[sizeof (gulong)];
	gint k;

	g_assert (cb);

	/* short form */
	if (len < 128) {
		if (ans != NULL)
			ans[0] = (unsigned char)len;
		*cb = 1;

	/* Long form */
	} else {
		k = 0;
		while (len) {
			temp[k++] = len & 0xFF;
			len = len >> 8;
		}
		*cb = k + 1;
		if (ans != NULL) {
			ans[0] = ((unsigned char) k & 0x7F) + 128;
			while (k--)
				ans[*cb - 1 - k] = temp[k];
		}
	}
}

static gint
atlv_unparse_cls_tag_len (guchar *data,
                          gsize n_data,
                          guchar cls,
                          gulong tag,
                          gint len)
{
	guchar temp[sizeof(gulong)];
	gint cb;
	gint off = 0;
	gint k;

	/* Short form */
	if (tag < 31) {
		off += 1;
		if (data) {
			g_assert (n_data >= off);
			data[0] = (cls & 0xE0) + ((guchar) (tag & 0x1F));
		}
	/* Long form */
	} else {
		k = 0;
		while (tag) {
			temp[k++] = tag & 0x7F;
			tag = tag >> 7;
		}
		off = k + 1;
		if (data) {
			g_assert (n_data >= off);
			data[0] = (cls & 0xE0) + 31;
			while (data && k--)
				data[off - 1 - k] = temp[k] + 128;
			data[off - 1] -= 128;
		}
	}

	/* And now the length */
	cb = n_data - off;
	atlv_unparse_len (len, data ? data + off : NULL, &cb);
	off += cb;

	g_assert (!data || n_data >= off);
	return off;
}

static void
atlv_unparse_der (Atlv *tlv,
                  guchar **at,
                  guchar *end)
{
	const guchar *exp;
	const guchar *buf;
	guchar *p;
	guchar mask;
	Atlv *ctlv;
	gint off;
	gsize len;

	g_assert (*at <= end);

	off = atlv_unparse_cls_tag_len (*at, end - *at, tlv->cls,
	                                tlv->tag, tlv->len);
	g_assert (off == tlv->off);
	(*at) += off;

	/* Write a value */
	if (tlv->value) {
		buf = g_bytes_get_data (tlv->value, &len);
		p = *at;

		/* Special behavior for bit strings */
		if (tlv->prefix_for_bit_string) {
			g_assert (len + 1 == tlv->len);
			p[0] = (guchar)tlv->bits_empty;
			memcpy (p + 1, buf, len);

			/* Set the extra bits to zero */
			if (len && tlv->bits_empty) {
				mask = 0xFF >> (8 - tlv->bits_empty);
				p[len] &= ~mask;
			}
			p += len + 1;

		/* Special behavior for prefixed integers */
		} else if (tlv->prefix_with_zero_byte) {
			g_assert (len + 1 == tlv->len);
			p[0] = 0;
			memcpy (p + 1, buf, len);
			p += len + 1;

		/* Standard behavior */
		} else {
			g_assert (len == tlv->len);
			memcpy (p, buf, len);
			p += len;
		}

		*at = p;

	/* Write a bunch of child TLV's */
	} else {
		for (ctlv = tlv->child; ctlv != NULL; ctlv = ctlv->next) {
			exp = *at + ctlv->len + ctlv->off;
			atlv_unparse_der (ctlv, at, end);
			g_assert (exp == *at);
		}
	}

	g_assert (*at <= end);
}

static GBytes *
atlv_unparse_to_bytes (Atlv *tlv,
                       EggAllocator allocator)
{
	GBytes *bytes;
	guchar *data;
	guchar *at;
	gint len;

	/* Allocate enough memory for entire thingy */
	len = tlv->off + tlv->len;
	g_return_val_if_fail (len != 0, NULL);

	bytes = bytes_new_with_allocator (allocator, &data, len);
	g_return_val_if_fail (bytes != NULL, NULL);

	at = data;
	atlv_unparse_der (tlv, &at, data + len);
	g_assert (at == data + len);

	return bytes;
}

typedef struct {
	GBytes *bytes;
	Atlv *tlv;
} SortPair;

static gint
compare_sort_pair (gconstpointer a,
                   gconstpointer b)
{
	const SortPair *sa = a;
	const SortPair *sb = b;
	return g_bytes_compare (sa->bytes, sb->bytes);
}

static void
atlv_sort_perform (Atlv *tlv,
                   EggAllocator allocator)
{
	GList *pairs, *l;
	SortPair *pair;
	GBytes *bytes;
	Atlv *ctlv;
	Atlv *last;
	gboolean sort;

	for (ctlv = tlv->child; ctlv != NULL; ctlv = ctlv->next)
		atlv_sort_perform (ctlv, allocator);

	if (!tlv->sorted)
		return;

	pairs = NULL;
	for (ctlv = tlv->child; ctlv != NULL; ctlv = ctlv->next) {
		bytes = atlv_unparse_to_bytes (ctlv, allocator);
		g_return_if_fail (bytes != NULL);

		pair = g_slice_new0 (SortPair);
		pair->bytes = bytes;
		pair->tlv = ctlv;
		pairs = g_list_prepend (pairs, pair);
	}

	/* Only sort of the above unparse completed for all */
	sort = ctlv == NULL;
	last = NULL;

	pairs = g_list_sort (pairs, compare_sort_pair);
	for (l = pairs; l != NULL; l = g_list_next (l)) {
		pair = l->data;

		/* Only if the sort completed */
		if (sort) {
			if (last == NULL)
				tlv->child = pair->tlv;
			else
				last->next = pair->tlv;
			last = pair->tlv;
		}

		g_bytes_unref (pair->bytes);
		g_slice_free (SortPair, pair);
	}

	g_list_free (pairs);
}

static void
anode_build_cls_tag_len (GNode *node,
                         Atlv *tlv,
                         gint len)
{
	gboolean explicit = FALSE;
	guchar cls_type;
	gint flags;

	/* One for the prefix character */
	if (tlv->prefix_for_bit_string ||
	    tlv->prefix_with_zero_byte)
		len += 1;

	/* Figure out the basis if the class */
	switch (anode_def_type (node)) {
	case EGG_ASN1X_INTEGER:
	case EGG_ASN1X_BOOLEAN:
	case EGG_ASN1X_BIT_STRING:
	case EGG_ASN1X_OCTET_STRING:
	case EGG_ASN1X_OBJECT_ID:
	case EGG_ASN1X_TIME:
	case EGG_ASN1X_UTC_TIME:
	case EGG_ASN1X_GENERALIZED_TIME:
	case EGG_ASN1X_ENUMERATED:
	case EGG_ASN1X_GENERAL_STRING:
	case EGG_ASN1X_NUMERIC_STRING:
	case EGG_ASN1X_IA5_STRING:
	case EGG_ASN1X_TELETEX_STRING:
	case EGG_ASN1X_PRINTABLE_STRING:
	case EGG_ASN1X_UNIVERSAL_STRING:
	case EGG_ASN1X_BMP_STRING:
	case EGG_ASN1X_UTF8_STRING:
	case EGG_ASN1X_VISIBLE_STRING:
	case EGG_ASN1X_NULL:
		tlv->cls = ASN1_CLASS_UNIVERSAL;
		break;
	/* Container types */
	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SET:
	case EGG_ASN1X_SEQUENCE_OF:
	case EGG_ASN1X_SET_OF:
		tlv->cls = (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL);
		break;

	/* Transparent types shouldn't get here */
	case EGG_ASN1X_ANY:
	case EGG_ASN1X_CHOICE:
	default:
		g_assert_not_reached ();
	};

	flags = anode_def_flags (node);

	/* Build up the class */
	if (flags & FLAG_TAG) {
		explicit = anode_calc_explicit_for_flags (node, flags, &cls_type);
		if (explicit)
			flags &= ~FLAG_TAG;
		else
			tlv->cls |= cls_type;
	}

	/* Setup the class */
	tlv->tag = anode_calc_tag_for_flags (node, flags);

	/* The offset and length */
	tlv->len = len;
	tlv->off = atlv_unparse_cls_tag_len (NULL, 0, tlv->cls, tlv->tag, len);
}

static Atlv *
anode_build_value (GNode *node)
{
	Anode *an = node->data;
	Atlv *tlv;
	gsize len;

	/* Fill this in based on the value */
	if (an->value == NULL)
		return NULL;

	tlv = atlv_new ();
	tlv->value = g_bytes_ref (an->value);

	len = g_bytes_get_size (an->value);
	anode_build_cls_tag_len (node, tlv, len);
	return tlv;
}

static Atlv *
anode_build_bit_string (GNode *node)
{
	Anode *an = node->data;
	Atlv *tlv;
	gsize len;

	if (an->value == NULL)
		return NULL;

	tlv = atlv_new ();
	tlv->value = g_bytes_ref (an->value);
	tlv->bits_empty = an->bits_empty;
	tlv->prefix_for_bit_string = 1;

	len = g_bytes_get_size (an->value);
	anode_build_cls_tag_len (node, tlv, len);
	return tlv;
}

static Atlv *
anode_build_integer (GNode *node)
{
	Anode *an = node->data;
	const guchar *buf;
	gboolean sign;
	gsize len;
	Atlv *tlv;

	if (an->value == NULL)
		return NULL;

	tlv = atlv_new ();
	tlv->value = g_bytes_ref (an->value);

	buf = g_bytes_get_data (an->value, &len);
	if (an->guarantee_unsigned) {

		/*
		 * In two's complement (which DER is) this would be negative, add a zero
		 * byte so that it isn't. Here we just note that the result will be one
		 * byte longer.
		 */
		sign = !!(buf[0] & 0x80);
		if (sign)
			tlv->prefix_with_zero_byte = 1;
	}

	anode_build_cls_tag_len (node, tlv, len);
	return tlv;
}

static Atlv *
anode_build_any (GNode *node)
{
	Atlv *parsed;

	/*
	 * Fill this in based on already parsed TLVs. It is assumed
	 * that any explicit tags are already present, and the functions
	 * for managing ANY try to enforce this.
	 */

	parsed = anode_get_parsed (node);
	if (parsed != NULL)
		return atlv_dup (parsed, FALSE);

	return NULL;
}

static Atlv *
anode_build_choice (GNode *node,
                    gboolean want)
{
	GNode *child;

	g_assert (anode_def_type (node) == EGG_ASN1X_CHOICE);

	child = egg_asn1x_get_choice (node);

	/* Should have been checked by a previous validate */
	g_return_val_if_fail (child != NULL, NULL);

	return anode_build_anything (child, want);
}

static Atlv *
anode_build_structured (GNode *node,
                        gboolean want)
{
	gboolean child_want;
	Atlv *last;
	Atlv *ctlv;
	Atlv *tlv;
	GNode *child;
	gint type;
	gint len;

	type = anode_def_type (node);
	child_want = want;
	last = NULL;
	len = 0;

	if (type == EGG_ASN1X_SEQUENCE_OF || type == EGG_ASN1X_SET_OF)
		child_want = FALSE;
	if (anode_def_flags (node) & FLAG_OPTION)
		want = FALSE;

	tlv = atlv_new ();
	for (child = node->children; child != NULL; child = child->next) {
		ctlv = anode_build_anything (child, child_want);
		if (ctlv != NULL) {
			if (last == NULL)
				tlv->child = ctlv;
			else
				last->next = ctlv;
			last = ctlv;
			len += ctlv->off + ctlv->len;
		}
	}

	if (last == NULL) {
		/* See if we should encode an empty set or seq of */
		if (type == EGG_ASN1X_SEQUENCE_OF || type == EGG_ASN1X_SET_OF) {
			if (!want) {
				atlv_free (tlv);
				return NULL;
			}
		} else if (!want) {
			atlv_free (tlv);
			return NULL;
		}
	}

	anode_build_cls_tag_len (node, tlv, len);

	if (type == EGG_ASN1X_SET_OF)
		tlv->sorted = 1;

	return tlv;
}

static Atlv *
anode_build_maybe_explicit (GNode *node,
                            Atlv *tlv,
                            gint flags)
{
	guchar cls_type;
	Atlv *wrap;

	/* Now wrap in explicit tag if that's the case */
	if (anode_calc_explicit_for_flags (node, flags, &cls_type)) {
		wrap = atlv_new ();
		wrap->cls = (ASN1_CLASS_STRUCTURED | cls_type);
		wrap->tag = anode_calc_tag (node);
		wrap->len = tlv->off + tlv->len;
		wrap->off = atlv_unparse_cls_tag_len (NULL, 0, wrap->cls, wrap->tag, wrap->len);
		wrap->child = tlv;
		tlv = wrap;
	}

	return tlv;
}

static Atlv *
anode_build_anything_for_flags (GNode *node,
                                gboolean want,
                                gint flags)
{
	Atlv *tlv;

	switch (anode_def_type (node)) {
	case EGG_ASN1X_BIT_STRING:
		tlv = anode_build_bit_string (node);
		break;
	case EGG_ASN1X_INTEGER:
		tlv = anode_build_integer (node);
		break;
	case EGG_ASN1X_BOOLEAN:
	case EGG_ASN1X_OCTET_STRING:
	case EGG_ASN1X_OBJECT_ID:
	case EGG_ASN1X_TIME:
	case EGG_ASN1X_UTC_TIME:
	case EGG_ASN1X_GENERALIZED_TIME:
	case EGG_ASN1X_ENUMERATED:
	case EGG_ASN1X_GENERAL_STRING:
	case EGG_ASN1X_NUMERIC_STRING:
	case EGG_ASN1X_IA5_STRING:
	case EGG_ASN1X_TELETEX_STRING:
	case EGG_ASN1X_PRINTABLE_STRING:
	case EGG_ASN1X_UNIVERSAL_STRING:
	case EGG_ASN1X_BMP_STRING:
	case EGG_ASN1X_UTF8_STRING:
	case EGG_ASN1X_VISIBLE_STRING:
	case EGG_ASN1X_NULL:
		tlv = anode_build_value (node);
		break;

	/* Any should already have explicit tagging, so just return */
	case EGG_ASN1X_ANY:
		return anode_build_any (node);

	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SEQUENCE_OF:
	case EGG_ASN1X_SET:
	case EGG_ASN1X_SET_OF:
		tlv = anode_build_structured (node, want);
		break;

	case EGG_ASN1X_CHOICE:
		tlv = anode_build_choice (node, want);
		break;

	default:
		g_assert_not_reached ();
	}

	if (tlv == NULL)
		return NULL;

	/* Now wrap in explicit tag if that's the case */
	return anode_build_maybe_explicit (node, tlv, flags);
}

static Atlv *
anode_build_anything (GNode *node,
                      gboolean want)
{
	return anode_build_anything_for_flags (node, want,
	                                       anode_def_flags (node));
}

GBytes *
egg_asn1x_encode (GNode *asn,
                  EggAllocator allocator)
{
	GBytes *bytes;
	Atlv *tlv;

	g_return_val_if_fail (asn != NULL, NULL);
	g_return_val_if_fail (anode_def_type_is_real (asn), NULL);

	if (!egg_asn1x_validate (asn, TRUE))
		return NULL;

	tlv = anode_build_anything (asn, TRUE);

	/* The above validate should cause build not to return NULL */
	g_return_val_if_fail (tlv != NULL, NULL);

	atlv_sort_perform (tlv, allocator);

	bytes = atlv_unparse_to_bytes (tlv, allocator);
	atlv_free (tlv);
	return bytes;
}

/* ----------------------------------------------------------------------------
 * VALUE READ/WRITE
 */

static int
two_to_four_digit_year (int year)
{
	time_t now;
	struct tm tm;
	int century, current;

	g_return_val_if_fail (year >= 0 && year <= 99, -1);

	/* Get the current year */
	now = time (NULL);
	g_return_val_if_fail (now >= 0, -1);
	if (!gmtime_r (&now, &tm))
		g_return_val_if_reached (-1);

	current = (tm.tm_year % 100);
	century = (tm.tm_year + 1900) - current;

	/*
	 * Check if it's within 40 years before the
	 * current date.
	 */
	if (current < 40) {
		if (year < current)
			return century + year;
		if (year > 100 - (40 - current))
			return (century - 100) + year;
	} else {
		if (year < current && year > (current - 40))
			return century + year;
	}

	/*
	 * If it's after then adjust for overflows to
	 * the next century.
	 */
	if (year < current)
		return century + 100 + year;
	else
		return century + year;
}

static gboolean
parse_utc_time (const gchar *time, gsize n_time,
                struct tm* when, gint *offset)
{
	const char *p, *e;
	int year;

	g_assert (when);
	g_assert (time);
	g_assert (offset);

	/* YYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 6 || n_time >= 28)
		return FALSE;

	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;

	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);

	if (p + 2 <= e) {
		year = atoin (p, 2);
		p += 2;

		/*
		 * 40 years in the past is our century. 60 years
		 * in the future is the next century.
		 */
		when->tm_year = two_to_four_digit_year (year) - 1900;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
		return FALSE;

	/* Make sure all that got parsed */
	if (p != e)
		return FALSE;

	/* Now the remaining optional stuff */
	e = time + n_time;

	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;

	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) {
		int off, neg;

		neg = *p == '-';
		++p;

		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return -1;
		p += 2;

		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */
		if (neg)
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */
	if (p != e)
		return FALSE;

	return TRUE;
}

static gboolean
parse_general_time (const gchar *time, gsize n_time,
                    struct tm* when, gint *offset)
{
	const char *p, *e;

	g_assert (time);
	g_assert (when);
	g_assert (offset);

	/* YYYYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 8 || n_time >= 30)
		return FALSE;

	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;

	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);

	if (p + 4 <= e) {
		when->tm_year = atoin (p, 4) - 1900;
		p += 4;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
		return FALSE;

	/* Make sure all that got parsed */
	if (p != e)
		return FALSE;

	/* Now the remaining optional stuff */
	e = time + n_time;

	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;

	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) {
		int off, neg;

		neg = *p == '-';
		++p;

		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return -1;
		p += 2;

		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */
		if (neg)
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */
	if (p != e)
		return FALSE;

	return TRUE;
}

static gboolean
anode_read_time (GNode *node,
                 GBytes *data,
                 struct tm *when,
                 glong *value)
{
	const gchar *buf;
	gboolean ret;
	gint offset = 0;
	gint flags;
	gint type;
	gsize len;

	g_assert (data != NULL);
	g_assert (when != NULL);
	g_assert (value != NULL);

	flags = anode_def_flags (node);
	type = anode_def_type (node);
	buf = g_bytes_get_data (data, &len);

	if (type == EGG_ASN1X_GENERALIZED_TIME)
		ret = parse_general_time (buf, len, when, &offset);
	else if (type == EGG_ASN1X_UTC_TIME)
		ret = parse_utc_time (buf, len, when, &offset);
	else if (flags & FLAG_GENERALIZED)
		ret = parse_general_time (buf, len, when, &offset);
	else if (flags & FLAG_UTC)
		ret = parse_utc_time (buf, len, when, &offset);
	else
		g_return_val_if_reached (FALSE);

	if (!ret)
		return anode_failure (node, "invalid time content");

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when->tm_year >= 2038) {
		*value = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		*value = timegm (when);
		g_return_val_if_fail (*value >= 0, FALSE);
		*value += offset;
	}

	return TRUE;
}

static gboolean
anode_read_integer_ulong (GNode *node,
                          GBytes *data,
                          gulong *value)
{
	const guchar *p;
	gsize len;
	gsize k;

	p = g_bytes_get_data (data, &len);
	if (len < 1 || len > sizeof (gulong))
		return FALSE;

	*value = 0;
	for (k = 0; k < len; ++k)
		*value |= p[k] << (8 * ((len - 1) - k));

	return TRUE;
}

static void
anode_write_integer_ulong (gulong value,
                           guchar *data,
                           gsize *n_data)
{
	guchar buf[sizeof (gulong)];
	gint bytes, i, off;
	guchar *at;
	gboolean sign;
	gsize len;

	for (i = 0; i < sizeof (gulong); ++i) {
		off = sizeof (gulong) - (i + 1);
		buf[i] = (value >> (off * 8)) & 0xFF;
	}

	for (bytes = sizeof (gulong) - 1; bytes >= 0; --bytes)
		if (!buf[bytes])
			break;

	bytes = sizeof (gulong) - (bytes + 1);
	if (bytes == 0)
		bytes = 1;

	/* If the first byte would make this negative, then add a zero */
	at = buf + (sizeof (gulong) - bytes);
	sign = !!(at[0] & 0x80);
	len = bytes + (sign ? 1 : 0);

	if (data) {
		g_assert (*n_data >= len);
		if (sign) {
			data[0] = 0;
			data++;
		}
		memcpy (data, at, bytes);
	}

	*n_data = len;
}

static GBytes *
anode_default_integer (GNode *node)
{
	const gchar *defval;
	EggAsn1xDef *opt;
	gchar *end;
	gulong value;
	guchar *data;
	gsize len;

	if (!(anode_def_flags (node) & FLAG_DEFAULT))
		return NULL;

	/* Try to get a default */
	opt = anode_opt_lookup (node, EGG_ASN1X_DEFAULT, NULL);
	g_return_val_if_fail (opt != NULL, NULL);
	g_return_val_if_fail (opt->value != NULL, NULL);
	defval = opt->value;

	opt = anode_opt_lookup (node, EGG_ASN1X_CONSTANT, defval);
	if (opt != NULL) {
		g_return_val_if_fail (opt->value != NULL, NULL);
		defval = opt->value;
	}

	/* Parse out the default value */
	value = strtoul (defval, &end, 10);
	g_return_val_if_fail (end && !end[0], NULL);

	anode_write_integer_ulong (value, NULL, &len);
	data = g_malloc (len);
	anode_write_integer_ulong (value, data, &len);
	return g_bytes_new_take (data, len);
}

static gboolean
anode_read_string_struct (GNode *node,
                          Atlv *tlv,
                          gpointer value,
                          gsize *n_value)
{
	const guchar *buf;
	gsize len;
	Atlv *ctlv;
	guchar *at;
	gint remaining;

	g_assert (tlv != NULL);
	g_assert (tlv->cls & ASN1_CLASS_STRUCTURED);
	g_assert (n_value != NULL);

	at = value;
	remaining = *n_value;
	*n_value = 0;

	for (ctlv = tlv->child; ctlv != NULL; ctlv = ctlv->next) {
		if (ctlv->cls & ASN1_CLASS_STRUCTURED ||
		    ctlv->value == NULL)
			return FALSE;
		buf = g_bytes_get_data (ctlv->value, &len);
		*n_value += len;
		if (value) {
			if (remaining >= len)
				memcpy (at, buf, len);
			at += len;
			remaining -= len;
		}
	}

	if (value)
		g_return_val_if_fail (remaining >= 0, FALSE);

	return TRUE;
}

static gboolean
anode_read_string_simple (GNode *node,
                          GBytes *data,
                          gpointer value,
                          gsize *n_value)
{
	const guchar *buf;
	gsize len;

	g_assert (data != NULL);
	g_assert (n_value != NULL);

	buf = g_bytes_get_data (data, &len);
	if (value) {
		g_return_val_if_fail (*n_value >= len, FALSE);
		memcpy (value, buf, len);
	}

	*n_value = len;
	return TRUE;
}

static gboolean
anode_read_boolean (GNode *node,
                    GBytes *data,
                    gboolean *value)
{
	const guchar *buf;
	gsize len;

	g_assert (node != NULL);
	g_assert (data != NULL);
	g_assert (value != NULL);

	buf = g_bytes_get_data (data, &len);
	g_return_val_if_fail (len == 1, FALSE);
	if (buf[0] == 0x00)
		*value = FALSE;
	else if (buf[0] == 0xFF)
		*value = TRUE;
	else
		g_return_val_if_reached (FALSE);
	return TRUE;
}

static void
anode_write_boolean (gboolean value,
                     guchar *data,
                     gsize *n_data)
{
	if (data) {
		g_assert (*n_data >= 1);
		if (value)
			data[0] = 0xFF;
		else
			data[0] = 0x00;
	}
	*n_data = 1;
}

static GBytes *
anode_default_boolean (GNode *node)
{
	EggAsn1xDef *opt;
	gboolean value;
	guchar *data;
	gsize len;

	if (!(anode_def_flags (node) & FLAG_DEFAULT))
		return NULL;

	/* Try to get a default */
	opt = anode_opt_lookup (node, EGG_ASN1X_DEFAULT, NULL);
	g_return_val_if_fail (opt != NULL, NULL);

	/* Parse out the default value */
	if ((opt->type & FLAG_TRUE) == FLAG_TRUE)
		value = TRUE;
	else if ((opt->type & FLAG_FALSE) == FLAG_FALSE)
		value = FALSE;
	else
		g_return_val_if_reached (FALSE);

	anode_write_boolean (value, NULL, &len);
	data = g_malloc (len);
	anode_write_boolean (value, data, &len);
	return g_bytes_new_take (data, len);
}

static gboolean
anode_read_object_id (GNode *node,
                      GBytes *data,
                      gchar **oid)
{
	GString *result = NULL;
	const guchar *p;
	gboolean lead;
	guint val, pval;
	gsize len;
	gint k;

	g_assert (data != NULL);
	p = g_bytes_get_data (data, &len);

	if (oid)
		result = g_string_sized_new (32);

	pval = p[0] / 40;
	val = p[0] - pval * 40;

	if (result)
		g_string_append_printf (result, "%u.%u", pval, val);

	/* TODO: Validate first byte? */
	for (k = 1, lead = 1, val = 0, pval = 0; k < len; ++k) {
		/* X.690: the leading byte must never be 0x80 */
		if (lead && p[k] == 0x80) {
			anode_failure (node, "object id encoding is invalid");
			break;
		}
		val = val << 7;
		val |= p[k] & 0x7F;
		/* Check for wrap around */
		if (val < pval) {
			anode_failure (node, "object id encoding is invalid");
			break;
		}
		pval = val;
		if (!(p[k] & 0x80)) {
			if (result)
				g_string_append_printf (result, ".%u", val);
			pval = val = 0;
			lead = 1;
		}
	}

	if (k < len) {
		if (result)
			g_string_free (result, TRUE); /* UNREACHABLE: caught by validation */
		return FALSE;
	}

	if (result)
		*oid = g_string_free (result, FALSE);
	return TRUE;
}

static gboolean
anode_write_object_id (const gchar *oid,
                       guchar *data,
                       gsize *n_data)
{
	const gchar *p, *next;
	gint num, num1;
	guchar bit7;
	gboolean had;
	gint i, k, at;

	at = 0;
	num1 = 0;

	for (i = 0; oid[0]; ++i, oid = next) {
		p = strchr (oid, '.');
		if (p == NULL)
			next = p = oid + strlen (oid);
		else
			next = p + 1;
		if (p == oid)
			return FALSE;
		num = atoin (oid, p - oid);
		if (num < 0)
			return FALSE;
		if (i == 0) {
			num1 = num;
		} else if (i == 1) {
			if (data) {
				g_assert (*n_data > at);
				data[at] = 40 * num1 + num;
			}
			++at;
		} else {
			for (had = FALSE, k = 4; k >= 0; k--) {
				bit7 = (num >> (k * 7)) & 0x7F;
				if (bit7 || had || !k) {
					if (k)
						bit7 |= 0x80;
					if (data) {
						g_assert (*n_data > at);
						data[at] = bit7;
					}
					++at;
					had = 1;
				}
			}
		}
	}

	if (at < 2)
		return FALSE;
	if (data)
		g_assert (*n_data >= at);
	*n_data = at;
	return TRUE;
}

/* -----------------------------------------------------------------------------------
 * GETTING, SETTING
 */

GNode*
egg_asn1x_node (GNode *asn, ...)
{
	GNode *node = asn;
	const gchar *name;
	va_list va;
	gint type;
	gint index;

	g_return_val_if_fail (asn, NULL);
	va_start (va, asn);

	for (;;) {
		type = anode_def_type (node);

		/* Use integer indexes for these */
		if (type == EGG_ASN1X_SEQUENCE_OF || type == EGG_ASN1X_SET_OF) {
			index = va_arg (va, gint);
			if (index == 0)
				return node;

			/* Only consider nodes that have data */
			node = g_node_nth_child (node, 0);
			while (node) {
				if (egg_asn1x_have (node)) {
					--index;
					if (index == 0)
						break;
				}
				node = g_node_next_sibling (node);
			}

			if (node == NULL)
				return NULL;

		/* Use strings for these */
		} else {
			name = va_arg (va, const gchar*);
			if (name == NULL)
				return node;
			/* Warn if they're using indexes here */
			if (name <= (const gchar*)4096) {
				g_warning ("possible misuse of egg_asn1x_node, expected a string, but got an index");
				return NULL;
			}
			node = anode_child_with_name (node, name);
			if (node == NULL)
				return NULL;
		}
	}
}

const gchar*
egg_asn1x_name (GNode *node)
{
	g_return_val_if_fail (node != NULL, NULL);
	return anode_def_name (node);
}

EggAsn1xType
egg_asn1x_type (GNode *node)
{
	g_return_val_if_fail (node != NULL, 0);
	return anode_def_type (node);
}

guint
egg_asn1x_count (GNode *node)
{
	guint result = 0;
	GNode *child;
	gint type;

	g_return_val_if_fail (node, 0);

	type = anode_def_type (node);
	if (type != EGG_ASN1X_SEQUENCE_OF && type != EGG_ASN1X_SET_OF) {
		g_warning ("node passed to egg_asn1x_count was not a sequence of or set of");
		return 0;
	}

	for (child = node->children; child; child = child->next) {
		if (egg_asn1x_have (child))
			++result;
	}

	return result;
}

GNode*
egg_asn1x_append (GNode *node)
{
	GNode *child;
	gint type;

	g_return_val_if_fail (node, NULL);

	type = anode_def_type (node);
	if (type != EGG_ASN1X_SEQUENCE_OF && type != EGG_ASN1X_SET_OF) {
		g_warning ("node passed to egg_asn1x_append was not a sequence of or set of");
		return NULL;
	}

	/* There must be at least one child */
	child = node->children;
	g_return_val_if_fail (child, NULL);

	child = anode_clone (child);
	anode_clear (child);
	g_node_append (node, child);

	return child;
}

gboolean
egg_asn1x_have (GNode *node)
{
	GNode *child;

	g_return_val_if_fail (node, FALSE);

	if (anode_get_value (node) || anode_get_parsed (node))
		return TRUE;

	for (child = node->children; child != NULL; child = child->next) {
		if (egg_asn1x_have (child))
			return TRUE;
	}

	return FALSE;
}

gboolean
egg_asn1x_get_boolean (GNode *node,
                       gboolean *value)
{
	gboolean ret;
	GBytes *data;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_BOOLEAN, FALSE);

	data = anode_get_value (node);
	if (data == NULL)
		data = anode_default_boolean (node);
	else
		g_bytes_ref (data);
	if (data == NULL)
		return FALSE;

	ret = anode_read_boolean (node, data, value);
	g_bytes_unref (data);
	return ret;
}

void
egg_asn1x_set_boolean (GNode *node, gboolean value)
{
	GBytes *data, *def;
	guchar *buf;
	gsize len;

	g_return_if_fail (node != NULL);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_BOOLEAN);

	len = 1;
	buf = g_malloc0 (1);
	anode_write_boolean (value, buf, &len);
	data = g_bytes_new_take (buf, len);

	/* If it's equal to default, then clear */
	def = anode_default_boolean (node);
	if (def) {
		if (g_bytes_equal (def, data)) {
			anode_clr_value (node);
			g_bytes_unref (data);
			data = NULL;
		}
		g_bytes_unref (def);
	}

	if (data != NULL)
		anode_take_value (node, data);
}

void
egg_asn1x_set_null (GNode *node)
{
	g_return_if_fail (node != NULL);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_NULL);

	/* Encode zero characters */
	anode_clr_value (node);
	anode_take_value (node, g_bytes_new_static ("", 0));
}

GQuark
egg_asn1x_get_enumerated (GNode *node)
{
	gchar buf[sizeof (gulong) * 3];
	EggAsn1xDef *opt;
	gulong val;
	GBytes *data;

	g_return_val_if_fail (node != NULL, 0);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_ENUMERATED, 0);

	data = anode_get_value (node);
	if (data == NULL)
		return 0;

	if (!anode_read_integer_ulong (node, data, &val))
		g_return_val_if_reached (0);

	/* Format that as a string */
	if (g_snprintf (buf, sizeof (buf), "%lu", val) < 0)
		g_return_val_if_reached (0);

	/* Lookup that value in our table */
	opt = anode_opt_lookup_value (node, EGG_ASN1X_CONSTANT, buf);
	if (opt == NULL || opt->name == NULL)
		return 0;

	return g_quark_from_static_string (opt->name);
}

void
egg_asn1x_set_enumerated (GNode *node,
                          GQuark value)
{
	EggAsn1xDef *opt;
	const gchar *name;
	gpointer data;
	gsize n_data;
	gulong val;

	g_return_if_fail (node != NULL);
	g_return_if_fail (value != 0);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_ENUMERATED);

	name = g_quark_to_string (value);
	g_return_if_fail (name != NULL);

	opt = anode_opt_lookup (node, EGG_ASN1X_CONSTANT, name);
	g_return_if_fail (opt && opt->value);

	/* TODO: Signed values */

	val = anode_def_value_as_ulong (opt);
	g_return_if_fail (val != G_MAXULONG);

	n_data = sizeof (gulong) + 1;
	data = g_malloc0 (n_data);
	anode_write_integer_ulong (val, data, &n_data);

	anode_clr_value (node);
	anode_take_value (node, g_bytes_new_take (data, n_data));
}

gboolean
egg_asn1x_get_integer_as_ulong (GNode *node,
                                gulong *value)
{
	gboolean ret;
	GBytes *data;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER, FALSE);

	data = anode_get_value (node);
	if (data == NULL)
		data = anode_default_integer (node);
	else
		g_bytes_ref (data);
	if (data == NULL)
		return FALSE;

	ret = anode_read_integer_ulong (node, data, value);
	g_bytes_unref (data);
	return ret;
}

void
egg_asn1x_set_integer_as_ulong (GNode *node,
                                gulong value)
{
	GBytes *data, *def;
	guchar *buf;
	gsize len;

	g_return_if_fail (node != NULL);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER);

	len = sizeof (gulong) + 1;
	buf = g_malloc0 (len);
	anode_write_integer_ulong (value, buf, &len);
	data = g_bytes_new_take (buf, len);

	/* If it's equal to default, then clear */
	def = anode_default_integer (node);
	if (def) {
		if (g_bytes_equal (def, data)) {
			anode_clr_value (node);
			g_bytes_unref (data);
			data = NULL;
		}
		g_bytes_unref (def);
	}

	if (data != NULL)
		anode_take_value (node, data);
}

GBytes *
egg_asn1x_get_integer_as_raw (GNode *node)
{
	Anode *an;
	GBytes *raw;

	g_return_val_if_fail (node != NULL, NULL);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER, NULL);

	an = node->data;
	if (an->guarantee_unsigned) {
		g_warning ("cannot read integer set with "        /* UNREACHABLE: */
		           "egg_asn1x_set_integer_as_raw() "      /* UNREACHABLE: */
		           "via egg_asn1x_get_integer_as_raw()"); /* UNREACHABLE: */
		return NULL;  /* UNREACHABLE: unreachable by coverage testing */
	}

	raw = anode_get_value (node);
	if (raw != NULL)
		g_bytes_ref (raw);
	return raw;
}

GBytes *
egg_asn1x_get_integer_as_usg (GNode *node)
{
	const guchar *p;
	Anode *an;
	gboolean sign;
	gsize len;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER, FALSE);

	an = node->data;
	if (an->value == NULL)
		return NULL;

	p = g_bytes_get_data (an->value, &len);

	if (!an->guarantee_unsigned) {
		sign = !!(p[0] & 0x80);
		if (sign) {
			g_warning ("invalid two's complement integer"); /* UNREACHABLE: */
			return NULL; /* UNREACHABLE: by coverage testing */
		}

		/* Strip off the extra zero byte that was preventing it from being negative */
		if (p[0] == 0 && len > 1) {
			sign = !!(p[1] & 0x80);
			if (sign) {
				p++;
				len--;
			}
		}
	}

	return g_bytes_new_with_free_func (p, len,
	                                   (GDestroyNotify)g_bytes_unref,
	                                   g_bytes_ref (an->value));
}

void
egg_asn1x_set_integer_as_raw (GNode *node,
                              GBytes *value)
{
	g_return_if_fail (value != NULL);
	egg_asn1x_take_integer_as_raw (node, g_bytes_ref (value));
}

void
egg_asn1x_take_integer_as_raw (GNode *node,
                               GBytes *value)
{
	gboolean sign;
	const guchar *p;
	Anode *an;

	g_return_if_fail (node != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER);

	/* Make sure the integer is properly encoded in twos complement*/
	p = g_bytes_get_data (value, NULL);
	g_return_if_fail (p != NULL);

	sign = !!(p[0] & 0x80);
	if (sign) {
		g_warning ("integer is not two's complement"); /* UNREACHABLE: */
		return; /* UNREACHABLE: unless warning */
	}

	anode_clr_value (node);
	anode_take_value (node, value);

	an = node->data;
	an->guarantee_unsigned = 0;
}

void
egg_asn1x_set_integer_as_usg (GNode *node,
                              GBytes *value)
{
	g_return_if_fail (value != NULL);
	egg_asn1x_take_integer_as_usg (node, g_bytes_ref (value));
}

void
egg_asn1x_take_integer_as_usg (GNode *node,
                               GBytes *value)
{
	Anode *an;

	g_return_if_fail (node != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (anode_def_type (node) == EGG_ASN1X_INTEGER);

	anode_take_value (node, value);
	an = node->data;
	an->guarantee_unsigned = 1;
}

GNode *
egg_asn1x_get_any_as (GNode *node,
                      const EggAsn1xDef *defs,
                      const gchar *type)
{
	g_return_val_if_fail (node != NULL, NULL);
	g_return_val_if_fail (type != NULL, NULL);
	g_return_val_if_fail (egg_asn1x_type (node) == EGG_ASN1X_ANY, NULL);

	return egg_asn1x_get_any_as_full (node, defs, type, 0);
}

GNode *
egg_asn1x_get_any_as_full (GNode *node,
                           const EggAsn1xDef *defs,
                           const gchar *type,
                           gint options)
{
	GNode *asn;

	g_return_val_if_fail (node != NULL, NULL);
	g_return_val_if_fail (type != NULL, NULL);
	g_return_val_if_fail (egg_asn1x_type (node) == EGG_ASN1X_ANY, NULL);

	asn = egg_asn1x_create (defs, type);
	g_return_val_if_fail (asn != NULL, NULL);

	if (!egg_asn1x_get_any_into_full (node, asn, options)) {
		egg_asn1x_destroy (asn);
		return NULL;
	}

	return asn;
}

gboolean
egg_asn1x_get_any_into  (GNode *node,
                         GNode *into)
{
	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (into != NULL, FALSE);
	g_return_val_if_fail (egg_asn1x_type (node) == EGG_ASN1X_ANY, FALSE);

	return egg_asn1x_get_any_into_full (node, into, 0);
}

gboolean
egg_asn1x_get_any_into_full (GNode *node,
                             GNode *into,
                             gint options)
{
	Atlv *tlv;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (into != NULL, FALSE);
	g_return_val_if_fail (egg_asn1x_type (node) == EGG_ASN1X_ANY, FALSE);

	tlv = anode_get_parsed (node);
	if (tlv == NULL)
		return FALSE;

	/* If this node is explicit, then just get the contents */
	if (anode_calc_explicit_for_flags (node, anode_def_flags (node), NULL)) {
		tlv = tlv->child;
		g_return_val_if_fail (tlv != NULL, FALSE);
	}

	if (!anode_decode_anything (into, tlv))
		return FALSE;

	return egg_asn1x_validate (into, !(options & EGG_ASN1X_NO_STRICT));
}

void
egg_asn1x_set_any_from (GNode *node,
                        GNode *from)
{
	Anode *an;
	Atlv *tlv;

	g_return_if_fail (node != NULL);
	g_return_if_fail (from != NULL);
	g_return_if_fail (egg_asn1x_type (node) == EGG_ASN1X_ANY);

	tlv = anode_build_anything (from, TRUE);
	g_return_if_fail (tlv != NULL);

	/* Wrap this in an explicit tag if necessary */
	tlv = anode_build_maybe_explicit (node, tlv, anode_def_flags (node));

	/* Mark down the tlvs for this node */
	an = node->data;
	atlv_free (an->parsed);
	an->parsed = tlv;
}

GBytes *
egg_asn1x_get_any_raw (GNode *node,
                       EggAllocator allocator)
{
	GBytes *bytes;
	Atlv *tlv;

	g_return_val_if_fail (node != NULL, NULL);

	tlv = anode_build_anything (node, TRUE);
	if (tlv == NULL) {
		anode_failure (node, "missing value(s)");
		return NULL;
	}

	atlv_sort_perform (tlv, allocator);

	bytes = atlv_unparse_to_bytes (tlv, allocator);
	atlv_free (tlv);
	return bytes;
}

gboolean
egg_asn1x_set_any_raw (GNode *node,
                       GBytes *raw)
{
	const gchar *msg;
	Anode *an;
	Atlv *tlv;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (raw != NULL, FALSE);

	an = node->data;
	tlv = atlv_new ();
	msg = atlv_parse_der (raw, tlv);
	if (msg == NULL) {

		/* Wrap this in an explicit tag if necessary */
		tlv = anode_build_maybe_explicit (node, tlv, anode_def_flags (node));

		atlv_free (an->parsed);
		an->parsed = tlv;
		return TRUE;

	/* A failure, set the message manually so it doesn't get a prefix */
	} else {
		atlv_free (tlv);
		an = node->data;
		g_free (an->failure);
		an->failure = g_strdup (msg);
		return FALSE;
	}
}

GBytes *
egg_asn1x_get_element_raw (GNode *node)
{
	Anode *an;
	Atlv *tlv;

	g_return_val_if_fail (node != NULL, NULL);

	an = node->data;
	tlv = an->parsed;

	/* If this node is explicit, then just get the contents */
	if (tlv && anode_calc_explicit_for_flags (node, anode_def_flags (node), NULL))
		tlv = tlv->child;

	if (!tlv || !tlv->decoded)
		return NULL;

	return g_bytes_ref (tlv->decoded);
}

GBytes *
egg_asn1x_get_value_raw (GNode *node)
{
	GBytes *raw;

	g_return_val_if_fail (node != NULL, NULL);
	raw = anode_get_value (node);
	if (raw != NULL)
		g_bytes_ref (raw);
	return raw;
}

guchar *
egg_asn1x_get_string_as_raw (GNode *node,
                             EggAllocator allocator,
                             gsize *n_string)
{
	gsize length;
	guchar *string;
	GBytes *data;
	Atlv *tlv;
	gint type;

	g_return_val_if_fail (node, NULL);
	g_return_val_if_fail (n_string, NULL);

	if (!allocator)
		allocator = g_realloc;

	type = anode_def_type (node);
	g_return_val_if_fail (type == EGG_ASN1X_OCTET_STRING ||
	                      type == EGG_ASN1X_GENERAL_STRING ||
	                      type == EGG_ASN1X_NUMERIC_STRING ||
	                      type == EGG_ASN1X_IA5_STRING ||
	                      type == EGG_ASN1X_TELETEX_STRING ||
	                      type == EGG_ASN1X_PRINTABLE_STRING ||
	                      type == EGG_ASN1X_UNIVERSAL_STRING ||
	                      type == EGG_ASN1X_BMP_STRING ||
	                      type == EGG_ASN1X_UTF8_STRING ||
	                      type == EGG_ASN1X_VISIBLE_STRING, NULL);

	data = anode_get_value (node);
	if (data != NULL) {
		if (!anode_read_string_simple (node, data, NULL, &length))
			g_return_val_if_reached (NULL);

		string = (allocator) (NULL, length + 1);
		if (string == NULL)
			return NULL; /* UNREACHABLE: unless odd allocator */

		if (!anode_read_string_simple (node, data, string, &length))
			g_return_val_if_reached (NULL);

		/* Courtesy null termination, string must however be validated! */
		string[length] = 0;
		*n_string = length;
		return string;
	}

	tlv = anode_get_parsed (node);
	if (tlv != NULL) {
		if (!anode_read_string_struct (node, tlv, NULL, &length))
			return NULL;

		string = (allocator) (NULL, length + 1);
		if (string == NULL)
			return NULL; /* UNREACHABLE: unless odd allocator */

		if (!anode_read_string_struct (node, tlv, string, &length))
			g_return_val_if_reached (NULL); /* should have failed above */

		/* Courtesy null termination, string must however be validated! */
		string[length] = 0;
		*n_string = length;
		return string;
	}

	return NULL;
}

void
egg_asn1x_set_string_as_raw (GNode *node,
                             guchar *data,
                             gsize n_data,
                             GDestroyNotify destroy)
{
	gint type;

	g_return_if_fail (node != NULL);
	g_return_if_fail (data != NULL);

	type = anode_def_type (node);
	g_return_if_fail (type == EGG_ASN1X_OCTET_STRING ||
	                  type == EGG_ASN1X_GENERAL_STRING ||
	                  type == EGG_ASN1X_NUMERIC_STRING ||
	                  type == EGG_ASN1X_IA5_STRING ||
	                  type == EGG_ASN1X_TELETEX_STRING ||
	                  type == EGG_ASN1X_PRINTABLE_STRING ||
	                  type == EGG_ASN1X_UNIVERSAL_STRING ||
	                  type == EGG_ASN1X_BMP_STRING ||
	                  type == EGG_ASN1X_UTF8_STRING ||
	                  type == EGG_ASN1X_VISIBLE_STRING);

	anode_take_value (node, g_bytes_new_with_free_func (data, n_data,
	                                                    destroy, data));
}

void
egg_asn1x_set_string_as_bytes (GNode *node,
                               GBytes *bytes)
{
	gint type;

	g_return_if_fail (node != NULL);
	g_return_if_fail (bytes != NULL);

	type = anode_def_type (node);
	g_return_if_fail (type == EGG_ASN1X_OCTET_STRING ||
	                  type == EGG_ASN1X_GENERAL_STRING ||
	                  type == EGG_ASN1X_NUMERIC_STRING ||
	                  type == EGG_ASN1X_IA5_STRING ||
	                  type == EGG_ASN1X_TELETEX_STRING ||
	                  type == EGG_ASN1X_PRINTABLE_STRING ||
	                  type == EGG_ASN1X_UNIVERSAL_STRING ||
	                  type == EGG_ASN1X_BMP_STRING ||
	                  type == EGG_ASN1X_UTF8_STRING ||
	                  type == EGG_ASN1X_VISIBLE_STRING);

	anode_set_value (node, bytes);
}

GBytes *
egg_asn1x_get_string_as_bytes (GNode *node)
{
	gpointer raw;
	gsize length;

	g_return_val_if_fail (node != NULL, NULL);

	raw = egg_asn1x_get_string_as_raw (node, NULL, &length);
	if (raw == NULL)
		return NULL;

	return g_bytes_new_take (raw, length);
}

gchar *
egg_asn1x_get_bmpstring_as_utf8 (GNode *node)
{
	gchar *string;
	gsize n_string;
	gchar *utf8;

	g_return_val_if_fail (node, NULL);

	string = (gchar*)egg_asn1x_get_string_as_raw (node, NULL, &n_string);
	if (!string)
		return NULL;

	utf8 = g_convert (string, n_string, "UTF-8", "UTF-16BE", NULL, NULL, NULL);
	g_free (string);

	return utf8;
}

gchar*
egg_asn1x_get_string_as_utf8 (GNode *node,
                              EggAllocator allocator)
{
	gchar *string;
	gsize n_string;

	g_return_val_if_fail (node, NULL);

	if (allocator == NULL)
		allocator = g_realloc;

	string = (gchar*)egg_asn1x_get_string_as_raw (node, allocator, &n_string);
	if (!string)
		return NULL;

	if (!g_utf8_validate (string, n_string, NULL)) {
		(allocator) (string, 0);
		return NULL;
	}

	return string;
}

gboolean
egg_asn1x_set_string_as_utf8 (GNode *node,
                              gchar *data,
                              GDestroyNotify destroy)
{
	gsize n_data;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	n_data = strlen (data);
	if (!g_utf8_validate (data, n_data, NULL))
		return FALSE;

	egg_asn1x_set_string_as_raw (node, (guchar*)data, n_data, destroy);
	return TRUE;
}

GBytes *
egg_asn1x_get_bits_as_raw (GNode *node,
                           guint *n_bits)
{
	gsize len;
	GBytes *data;
	Anode *an;

	g_return_val_if_fail (node != NULL, NULL);
	g_return_val_if_fail (n_bits != NULL, NULL);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_BIT_STRING, NULL);

	data = anode_get_value (node);
	if (data == NULL)
		return NULL;

	len = g_bytes_get_size (data);
	an = node->data;

	*n_bits = (len * 8) - an->bits_empty;
	return g_bytes_ref (data);
}

void
egg_asn1x_set_bits_as_raw (GNode *node,
                           GBytes *value,
                           guint n_bits)
{
	g_return_if_fail (node != NULL);
	g_return_if_fail (value != NULL);

	egg_asn1x_take_bits_as_raw (node, g_bytes_ref (value), n_bits);
}

void
egg_asn1x_take_bits_as_raw (GNode *node,
                            GBytes *value,
                            guint n_bits)
{
	Anode *an;
	gint type;
	gsize len;
	guchar empty;

	g_return_if_fail (node != NULL);
	g_return_if_fail (value != NULL);

	type = anode_def_type (node);
	g_return_if_fail (type == EGG_ASN1X_BIT_STRING);

	len = (n_bits / 8);
	if (n_bits % 8)
		len += 1;

	empty = n_bits % 8;
	if (empty > 0)
		empty = 8 - empty;

	anode_take_value (node, value);
	an = node->data;
	an->bits_empty = empty;
}

gboolean
egg_asn1x_get_bits_as_ulong (GNode *node,
                             gulong *bits,
                             guint *n_bits)
{
	GBytes *data;
	const guchar *buf;
	gsize len;
	guint i, length;
	guchar empty;
	const guchar *p;
	gulong value;
	Anode *an;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (bits != NULL, FALSE);
	g_return_val_if_fail (n_bits != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_BIT_STRING, FALSE);

	data = anode_get_value (node);
	if (data == NULL)
		return FALSE;

	buf = g_bytes_get_data (data, &len);
	an = node->data;
	empty = an->bits_empty;

	length = (len * 8) - empty;
	if (length > sizeof (gulong) * 8)
		return FALSE;

	value = 0;
	p = buf;

	for (i = 0; i < len; ++i)
		value = value << 8 | p[i];

	*bits = value >> empty;
	*n_bits = length;
	return TRUE;
}

void
egg_asn1x_set_bits_as_ulong (GNode *node,
                             gulong bits,
                             guint n_bits)
{
	guchar *data;
	gulong value;
	gsize i, len;
	guchar empty;
	Anode *an;
	gint type;

	g_return_if_fail (node != NULL);
	g_return_if_fail (n_bits <= sizeof (gulong) * 8);

	type = anode_def_type (node);
	g_return_if_fail (type == EGG_ASN1X_BIT_STRING);

	empty = n_bits % 8;
	if (empty > 0)
		empty = 8 - empty;
	len = (n_bits / 8) + (empty ? 1 : 0);

	data = g_malloc0 (sizeof (gulong));
	value = bits << empty;

	for (i = 0; i < len; ++i)
		data[len - i - 1] = (value >> i * 8) & 0xFF;

	an = node->data;
	an->bits_empty = empty;
	anode_take_value (node, g_bytes_new_take (data, len));
}

glong
egg_asn1x_get_time_as_long (GNode *node)
{
	struct tm when;
	GBytes *data;
	glong time;
	gint type;

	g_return_val_if_fail (node, -1);
	type = anode_def_type (node);

	/* Time is often represented as a choice, so work than in here */
	if (type == EGG_ASN1X_CHOICE) {
		node = egg_asn1x_get_choice (node);
		if (node == NULL)
			return -1;
		g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_TIME ||
		                      anode_def_type (node) == EGG_ASN1X_UTC_TIME ||
		                      anode_def_type (node) == EGG_ASN1X_GENERALIZED_TIME, -1);
		return egg_asn1x_get_time_as_long (node);
	}

	g_return_val_if_fail (type == EGG_ASN1X_TIME ||
	                      type == EGG_ASN1X_UTC_TIME ||
	                      type == EGG_ASN1X_GENERALIZED_TIME, -1);

	data = anode_get_value (node);
	if (data == NULL)
		return -1;

	if (!anode_read_time (node, data, &when, &time))
		g_return_val_if_reached (-1); /* already validated */
	return time;
}

gboolean
egg_asn1x_get_time_as_date (GNode *node,
                            GDate *date)
{
	struct tm when;
	GBytes *data;
	glong time;
	gint type;

	g_return_val_if_fail (node, FALSE);
	type = anode_def_type (node);

	/* Time is often represented as a choice, so work than in here */
	if (type == EGG_ASN1X_CHOICE) {
		node = egg_asn1x_get_choice (node);
		if (node == NULL)
			return FALSE;
		g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_TIME ||
		                      anode_def_type (node) == EGG_ASN1X_UTC_TIME ||
		                      anode_def_type (node) == EGG_ASN1X_GENERALIZED_TIME, FALSE);
		return egg_asn1x_get_time_as_date (node, date);
	}

	g_return_val_if_fail (type == EGG_ASN1X_TIME ||
	                      type == EGG_ASN1X_UTC_TIME ||
	                      type == EGG_ASN1X_GENERALIZED_TIME, FALSE);

	data = anode_get_value (node);
	if (data == NULL)
		return FALSE;

	if (!anode_read_time (node, data, &when, &time))
		g_return_val_if_reached (FALSE); /* already validated */

	g_date_set_dmy (date, when.tm_mday, when.tm_mon + 1, when.tm_year + 1900);
	return TRUE;
}

gchar*
egg_asn1x_get_oid_as_string (GNode *node)
{
	GBytes *data;
	gchar *oid;

	g_return_val_if_fail (node, NULL);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_OBJECT_ID, NULL);

	data = anode_get_value (node);
	if (data == NULL)
		return NULL;

	if (!anode_read_object_id (node, data, &oid))
		g_return_val_if_reached (NULL); /* should have been validated */

	return oid;
}

gboolean
egg_asn1x_set_oid_as_string (GNode *node,
                             const gchar *oid)
{
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (oid != NULL, FALSE);
	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_OBJECT_ID, FALSE);

	/* Encoding will always be shorter than string */
	n_data = strlen (oid);
	data = g_malloc0 (n_data);

	if (!anode_write_object_id (oid, data, &n_data)) {
		g_free (data);
		return FALSE;
	}

	anode_take_value (node, g_bytes_new_take (data, n_data));
	return TRUE;
}

GQuark
egg_asn1x_get_oid_as_quark (GNode *node)
{
	GQuark quark;
	gchar *oid;

	oid = egg_asn1x_get_oid_as_string (node);
	if (!oid)
		return 0;
	quark = g_quark_from_string (oid);
	g_free (oid);
	return quark;
}

gboolean
egg_asn1x_set_oid_as_quark (GNode *node,
                            GQuark oid)
{
	const gchar *str;

	g_return_val_if_fail (oid != 0, FALSE);

	str = g_quark_to_string (oid);
	g_return_val_if_fail (str != NULL, FALSE);

	return egg_asn1x_set_oid_as_string (node, str);
}

GNode*
egg_asn1x_get_choice (GNode *node)
{
	GNode *child;
	Anode *an;

	g_return_val_if_fail (node, NULL);

	/* One and only one of the children must be set */
	for (child = node->children; child; child = child->next) {
		an = (Anode*)child->data;
		if (an->chosen)
			return child;
	}

	return NULL;
}

gboolean
egg_asn1x_set_choice (GNode *node,
                      GNode *choice)
{
	GNode *child;
	Anode *an;

	g_return_val_if_fail (node != NULL, FALSE);
	g_return_val_if_fail (anode_def_type (node) == EGG_ASN1X_CHOICE, FALSE);

	/* One and only one of the children must be set */
	for (child = node->children; child; child = child->next) {
		an = (Anode*)child->data;
		if (child == choice) {
			an->chosen = 1;
			choice = NULL;
		} else {
			an->chosen = 0;
		}
	}

	/* The choice is not one of the child nodes */
	g_return_val_if_fail (!choice, FALSE);

	return TRUE;
}

/* -----------------------------------------------------------------------------------
 * VALIDATION
 */

static gboolean
anode_parse_size (GNode *node,
                  const gchar *text,
                  gulong *value)
{
	EggAsn1xDef *def;
	gchar *end = NULL;

	if (text == NULL) {
		*value = 0;
		return FALSE;
	} else if (g_str_equal (text, "MAX")) {
		*value = G_MAXULONG;
		return TRUE;
	} else if (g_ascii_isalpha (text[0])) {
		def = anode_opt_lookup (node, EGG_ASN1X_INTEGER, text);
		g_return_val_if_fail (def, FALSE);
		return anode_parse_size (node, def->value, value);
	}

	*value = strtoul (text, &end, 10);
	g_return_val_if_fail (end && !end[0], FALSE);
	return TRUE;
}


static gboolean
anode_validate_size (GNode *node,
                     gulong length)
{
	EggAsn1xDef *size;
	gulong value1 = 0;
	gulong value2 = G_MAXULONG;

	if (anode_def_flags (node) & FLAG_SIZE) {
		size = anode_opt_lookup (node, EGG_ASN1X_SIZE, NULL);
		g_return_val_if_fail (size, FALSE);
		if (!anode_parse_size (node, size->value, &value1))
			g_return_val_if_reached (FALSE);
		if (size->type & FLAG_MIN_MAX) {
			if (!anode_parse_size (node, size->name, &value2))
				g_return_val_if_reached (FALSE);
			if (length < value1 || length >= value2)
				return anode_failure (node, "content size is out of bounds");
		} else {
			if (length != value1)
				return anode_failure (node, "content size is not correct");
		}
	}

	return TRUE;
}

static gboolean
anode_validate_integer (GNode *node,
                        GBytes *value)
{
	GList *constants, *l;
	gulong val, check;
	gsize len;
	gboolean found;
	gint flags;

	g_assert (value != NULL);
	len = g_bytes_get_size (value);

	/* Integers must be at least one byte long */
	if (len == 0)
		return anode_failure (node, "zero length integer");

	flags = anode_def_flags (node);
	if (flags & FLAG_LIST) {
		/* Parse out the value, we only support small integers*/
		if (!anode_read_integer_ulong (node, value, &val))
			return anode_failure (node, "integer not part of list");

		/* Look through the list of constants */
		found = FALSE;
		constants = anode_opts_lookup (node, EGG_ASN1X_CONSTANT, NULL);
		for (l = constants; l; l = g_list_next (l)) {
			check = anode_def_value_as_ulong (l->data);
			g_return_val_if_fail (check != G_MAXULONG, FALSE);
			if (check == val) {
				found = TRUE;
				break;
			}
		}
		g_list_free (constants);

		if (!found)
			return anode_failure (node, "integer not part of listed set");
	}

	return TRUE;
}

static gboolean
anode_validate_enumerated (GNode *node,
                           GBytes *value)
{
	const guchar *buf;
	gsize length;

	g_assert (value != NULL);

	buf = g_bytes_get_data (value, &length);

	/* Enumerated must be positive */
	if (length > 0 && (buf[0] & 0x80))
		return anode_failure (node, "enumerated must be positive");

	return anode_validate_integer (node, value);
}

static gboolean
anode_validate_boolean (GNode *node,
                        GBytes *value)
{
	const guchar *buf;
	gsize len;

	g_assert (value != NULL);
	buf = g_bytes_get_data (value, &len);

	/* Must one byte, and zero or all ones */
	if (len != 1)
		return anode_failure (node, "invalid length boolean");
	if (buf[0] != 0x00 && buf[0] != 0xFF)
		return anode_failure (node, "boolean must be true or false");
	return TRUE;
}

static gboolean
anode_validate_bit_string (GNode *node,
                           GBytes *value)
{
	g_assert (value != NULL);

	/* All the decode validation done in anode_decode_bit_string */
	return TRUE;
}

static gboolean
anode_validate_string (GNode *node,
                       GBytes *value)
{
	gsize length;

	if (!anode_read_string_simple (node, value, NULL, &length))
		g_return_val_if_reached (FALSE);

	return anode_validate_size (node, (gulong)length);
}

static gboolean
anode_validate_object_id (GNode *node,
                          GBytes *value)
{
	return anode_read_object_id (node, value, NULL);
}

static gboolean
anode_validate_null (GNode *node,
                     GBytes *value)
{
	g_assert (value != NULL);
	return (g_bytes_get_size (value) == 0);
}

static gboolean
anode_validate_time (GNode *node,
                     GBytes *value)
{
	glong time;
	struct tm when;
	return anode_read_time (node, value, &when, &time);
}

static gboolean
anode_validate_choice (GNode *node,
                       gboolean strict)
{
	GNode *child, *choice;
	Anode *an;

	/* One and only one of the children must be set */
	choice = egg_asn1x_get_choice (node);
	if (!choice)
		return anode_failure (node, "one choice must be set");

	if (!anode_validate_anything (choice, strict))
		return FALSE;

	for (child = node->children; child; child = child->next) {
		if (child != choice) {
			an = (Anode*)child->data;
			if (an->chosen)
				return anode_failure (node, "only one choice may be set");
		}
	}

	return TRUE;
}

static gboolean
anode_validate_sequence_or_set (GNode *node,
                                gboolean strict)
{
	GNode *child;

	/* If this is optional, and has no values, then that's all good */
	if (anode_def_flags (node) & FLAG_OPTION) {
		if (!egg_asn1x_have (node))
			return TRUE;
	}

	/* All of the children must validate properly */
	for (child = node->children; child; child = child->next) {
		if (!anode_validate_anything (child, strict))
			return FALSE;
	}

	return TRUE;
}

static gboolean
anode_validate_sequence_or_set_of (GNode *node,
                                   gboolean strict)
{
	GNode *child;
	gulong count;

	count = 0;

	/* All the children must validate properly */
	for (child = node->children; child; child = child->next) {
		if (egg_asn1x_have (child)) {
			if (!anode_validate_anything (child, strict))
				return FALSE;
			count++;
		}
	}

	if (count == 0 && anode_def_flags (node) & FLAG_OPTION)
		return TRUE;

	return anode_validate_size (node, count);
}

static gboolean
anode_validate_anything (GNode *node,
                         gboolean strict)
{
	GBytes *value;
	Atlv *tlv;
	gint type;
	gint flags;

	type = anode_def_type (node);
	flags = anode_def_flags (node);

	/* Handle these specially */
	switch (type) {
	case EGG_ASN1X_CHOICE:
		return anode_validate_choice (node, strict);

	case EGG_ASN1X_SEQUENCE:
	case EGG_ASN1X_SET:
		return anode_validate_sequence_or_set (node, strict);

	case EGG_ASN1X_SEQUENCE_OF:
	case EGG_ASN1X_SET_OF:
		return anode_validate_sequence_or_set_of (node, strict);

	default:
		break;
	}

	/* Values that have been configured */
	value = anode_get_value (node);
	if (value) {
		switch (type) {
		case EGG_ASN1X_INTEGER:
			return anode_validate_integer (node, value);
		case EGG_ASN1X_ENUMERATED:
			return anode_validate_enumerated (node, value);
		case EGG_ASN1X_BOOLEAN:
			return anode_validate_boolean (node, value);
		case EGG_ASN1X_BIT_STRING:
			return anode_validate_bit_string (node, value);
		case EGG_ASN1X_OCTET_STRING:
		case EGG_ASN1X_GENERAL_STRING:
		case EGG_ASN1X_NUMERIC_STRING:
		case EGG_ASN1X_IA5_STRING:
		case EGG_ASN1X_TELETEX_STRING:
		case EGG_ASN1X_PRINTABLE_STRING:
		case EGG_ASN1X_UTF8_STRING:
		case EGG_ASN1X_VISIBLE_STRING:
			return anode_validate_string (node, value);
		case EGG_ASN1X_BMP_STRING:
		case EGG_ASN1X_UNIVERSAL_STRING:
			return TRUE; /* TODO: Need to validate strings more completely */
		case EGG_ASN1X_OBJECT_ID:
			return anode_validate_object_id (node, value);
		case EGG_ASN1X_NULL:
			return anode_validate_null (node, value);
		case EGG_ASN1X_TIME:
		case EGG_ASN1X_UTC_TIME:
		case EGG_ASN1X_GENERALIZED_TIME:
			return anode_validate_time (node, value);
		default:
			g_assert_not_reached ();
		}
	}

	/* See if there's a tlv parsed */
	tlv = anode_get_parsed (node);
	if (tlv) {
		switch (type) {
		case EGG_ASN1X_ANY:
		case EGG_ASN1X_GENERAL_STRING:
		case EGG_ASN1X_OCTET_STRING:
		case EGG_ASN1X_NUMERIC_STRING:
		case EGG_ASN1X_IA5_STRING:
		case EGG_ASN1X_TELETEX_STRING:
		case EGG_ASN1X_PRINTABLE_STRING:
		case EGG_ASN1X_UTF8_STRING:
		case EGG_ASN1X_VISIBLE_STRING:
		case EGG_ASN1X_BMP_STRING:
		case EGG_ASN1X_UNIVERSAL_STRING:
			return TRUE;
		default:
			break; /* UNREACHABLE: fix compiler warning */
		}
	}

	if (flags & FLAG_OPTION)
		return TRUE;
	if (flags & FLAG_DEFAULT)
		return TRUE;
	return anode_failure (node, "missing value");
}

gboolean
egg_asn1x_validate (GNode *asn,
                    gboolean strict)
{
	g_return_val_if_fail (asn, FALSE);
	return anode_validate_anything (asn, strict);
}

/* -----------------------------------------------------------------------------------
 * TREE CREATION
 */

static gint
compare_nodes_by_tag (gconstpointer a, gconstpointer b)
{
	GNode *na = (gpointer)a;
	GNode *nb = (gpointer)b;
	gulong taga, tagb;

	g_return_val_if_fail (anode_def_flags (na) & FLAG_TAG, 0);
	g_return_val_if_fail (anode_def_flags (nb) & FLAG_TAG, 0);

	taga = anode_calc_tag (na);
	g_return_val_if_fail (taga != G_MAXULONG, 0);

	tagb = anode_calc_tag (nb);
	g_return_val_if_fail (tagb != G_MAXULONG, 0);

	if (taga == tagb)
		return 0;
	return (taga < tagb) ? -1 : 1;
}

static const EggAsn1xDef *
adef_next_sibling (const EggAsn1xDef *def)
{
	int depth = 0;

	g_assert (def);
	g_assert (def->value || def->type || def->name);

	if ((def->type & FLAG_RIGHT) == 0)
		return NULL;

	/* Skip past any children */
	if ((def->type & FLAG_DOWN) == FLAG_DOWN) {
		depth += 1;
		while (depth > 0) {
			++def;
			if ((def->type & FLAG_DOWN) == FLAG_DOWN)
				depth += 1;
			if ((def->type & FLAG_RIGHT) == 0)
				depth -= 1;
		}
	}

	++def;
	g_return_val_if_fail (def->value || def->type || def->name, NULL);
	return def;
}

static const EggAsn1xDef *
adef_first_child (const EggAsn1xDef *def)
{
	g_assert (def);
	g_assert (def->value || def->type || def->name);

	if ((def->type & FLAG_DOWN) == 0)
		return NULL;

	++def;
	g_return_val_if_fail (def->value || def->type || def->name, NULL);
	return def;
}

static const EggAsn1xDef *
lookup_def_of_type (const EggAsn1xDef *defs,
                    const gchar *name,
                    gint type)
{
	const EggAsn1xDef *def;

	g_assert (defs);
	g_assert (defs->value || defs->type || defs->name);

	for (def = adef_first_child (defs); def; def = adef_next_sibling (def)) {
		if ((def->type & 0xFF) == type && def->name && g_str_equal (name, def->name))
			return def;
	}

	return NULL;
}

static gboolean
traverse_and_prepare (GNode *node, gpointer data)
{
	const EggAsn1xDef *defs = data;
	const EggAsn1xDef *def;
	const gchar *identifier;
	Anode *an, *anj;
	GNode *join = NULL;
	GNode *child, *next;
	GList *list = NULL, *l;

	/* A while, because the stuff we join, could also be an identifier */
	while (anode_def_type (node) == EGG_ASN1X_IDENTIFIER) {
		an = node->data;
		identifier = an->join ? an->join->value : an->def->value;
		g_return_val_if_fail (identifier, TRUE);
		egg_asn1x_destroy (join);
		join = egg_asn1x_create (defs, identifier);
		g_return_val_if_fail (join, TRUE);
		anj = join->data;
		an->join = anj->def;
	}

	/* Move all the children of join node into our node */
	if (join) {
		list = NULL;
		for (child = join->children, list = NULL; child; child = child->next)
			list = g_list_prepend (list, child);
		list = g_list_reverse (list);
		for (l = list; l; l = g_list_next (l)) {
			child = l->data;
			g_node_unlink (child);
			g_node_append (node, child);
		}
		g_list_free (list);
		list = NULL;
	}

	/* Lookup the max set size */
	if (anode_def_type (node) == EGG_ASN1X_SIZE) {
		identifier = anode_def_name (node);
		if (identifier && !g_str_equal (identifier, "MAX") &&
		    g_ascii_isalpha (identifier[0])) {
			def = lookup_def_of_type (defs, identifier, EGG_ASN1X_INTEGER);
			g_return_val_if_fail (def, TRUE);
			anode_opt_add (node, def);
		}
	}

	/* Anything child not a real node, we put into opts */
	if (anode_def_type_is_real (node)) {
		child = node->children;
		while (child) {
			next = child->next;
			if (!anode_def_type_is_real (child)) {
				an = child->data;
				anode_opt_add (node, an->def);
				for (l = an->opts; l; l = g_list_next (l))
					anode_opt_add (node, l->data);
				g_node_unlink (child);
				anode_destroy (child);
			}
			child = next;
		}
	}

	if (join) {
		an = join->data;
		for (l = an->opts; l; l = g_list_next (l))
			anode_opt_add (node, l->data);
		egg_asn1x_destroy (join);
	}

	/* Sort the children of any sets */
	if (anode_def_type (node) == EGG_ASN1X_SET) {
		for (child = node->children; child; child = child->next)
			list = g_list_prepend (list, child);
		list = g_list_sort (list, compare_nodes_by_tag);
		for (l = list; l; l = g_list_next (l))
			g_node_unlink (l->data);
		for (l = list; l; l = g_list_next (l))
			g_node_append (node, l->data);
		g_list_free (list);
		list = NULL;
	}

	/* Continue traversal */
	return FALSE;
}

static const EggAsn1xDef *
match_oid_in_definition (const EggAsn1xDef *def,
                         GHashTable *names,
                         const gchar *match,
                         const gchar **problem)
{
	const EggAsn1xDef *result = NULL;
	const EggAsn1xDef *odef;
	const gchar *value;
	GString *oid = NULL;

	g_assert (match);
	g_assert (problem);
	g_assert (names);

	for (odef = adef_first_child (def); odef; odef = adef_next_sibling (odef)) {
		if ((odef->type & 0xFF) != EGG_ASN1X_CONSTANT)
			continue;

		g_return_val_if_fail (odef->value, NULL);
		if (strspn (odef->value, "01234567890") == strlen (odef->value)) {
			value = odef->value;

		} else {
			value = g_hash_table_lookup (names, odef->value);

			/* A name resolution problem */
			if (!value) {
				if (oid)
					g_string_free (oid, TRUE);
				*problem = odef->value;
				return NULL;
			}
		}

		if (oid) {
			g_string_append_c (oid, '.');
			g_string_append (oid, value);
		} else {
			oid = g_string_new (value);
		}
	}

	if (oid != NULL) {
		if (g_str_equal (oid->str, match))
			result = adef_next_sibling (def);
		g_assert (def->name);
		g_hash_table_insert (names, (gchar*)def->name, g_string_free (oid, FALSE));
	}

	return result;
}

static const EggAsn1xDef *
match_oid_in_definitions (const EggAsn1xDef *defs,
                          const gchar *match)
{
	const EggAsn1xDef *def;
	const EggAsn1xDef *result;
	GHashTable *names;
	gboolean progress;
	const gchar *problem;

	names = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	result = NULL;

	for (;;) {
		progress = FALSE;
		problem = NULL;

		for (def = adef_first_child (defs); def; def = adef_next_sibling (def)) {

			/* Only work with object ids, and ones with names */
			if ((def->type & 0xFF) != EGG_ASN1X_OBJECT_ID || !def->name)
				continue;

			/* If we've already seen this one, skip */
			if (g_hash_table_lookup (names, def->name))
				continue;

			progress = TRUE;
			result = match_oid_in_definition (def, names, match, &problem);
			if (result != NULL)
				break;
		}

		if (!problem || result) {
			break;
		} else if (problem && !progress) {
			g_warning ("couldn't find oid definition in ASN.1 for: %s", problem);
			g_return_val_if_reached (NULL);
		}
	}

	g_hash_table_destroy (names);
	return result;
}

static gboolean
is_oid_number (const gchar *p)
{
	gboolean must = TRUE;
	gint i;

	for (i = 0; p[i] != '\0'; i++) {
		if (g_ascii_isdigit (p[i])) {
			must = FALSE;
		} else if (must) {
			return FALSE;
		} else {
			if (p[i] != '.')
				return FALSE;
			must = TRUE;
		}
	}

	return !must;
}

GNode*
egg_asn1x_create (const EggAsn1xDef *defs,
                  const gchar *type)
{
	const EggAsn1xDef *def;
	GNode *root, *parent, *node;
	int flags;

	g_return_val_if_fail (defs, NULL);
	g_return_val_if_fail (type, NULL);

	/* An OID */
	if (is_oid_number (type)) {
		def = match_oid_in_definitions (defs, type);

	/* An Identifier */
	} else {
		for (def = adef_first_child (defs); def; def = adef_next_sibling (def)) {
			if (def->name && g_str_equal (type, def->name))
				break;
		}
	}

	if (def == NULL || !def->name || !def->type)
		return NULL;

	/* The node for this item */
	root = anode_new (def);

	/* Build up nodes for underlying level */
	if (def->type & FLAG_DOWN) {
		node = root;
		for (;;) {
			if (def->type & FLAG_DOWN) {
				parent = node;
			} else if (def->type & FLAG_RIGHT) {
				g_assert (node->parent);
				parent = node->parent;
			} else {
				parent = node->parent;
				while (parent) {
					flags = anode_def_flags (parent);
					parent = parent->parent;
					if (flags & FLAG_RIGHT)
						break;
				}
			}

			if (!parent)
				break;

			++def;
			node = anode_new (def);
			g_node_append (parent, node);
		}
	}

	/* Load up sub identifiers */
	g_node_traverse (root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
	                 traverse_and_prepare, (gpointer)defs);

	return root;
}

GNode*
egg_asn1x_create_quark (const EggAsn1xDef *defs,
                        GQuark type)
{
	g_return_val_if_fail (type, NULL);
	return egg_asn1x_create (defs, g_quark_to_string (type));
}

GNode *
egg_asn1x_create_and_decode_full (const EggAsn1xDef *defs,
                                  const gchar *identifier,
                                  GBytes *data,
                                  gint options)
{
	GNode *asn;

	g_return_val_if_fail (defs != NULL, NULL);
	g_return_val_if_fail (identifier != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	asn = egg_asn1x_create (defs, identifier);
	g_return_val_if_fail (asn, NULL);

	if (!egg_asn1x_decode_full (asn, data, options)) {
		egg_asn1x_destroy (asn);
		return NULL;
	}

	return asn;

}

GNode*
egg_asn1x_create_and_decode (const EggAsn1xDef *defs,
                             const gchar *identifier,
                             GBytes *data)
{
	g_return_val_if_fail (defs != NULL, NULL);
	g_return_val_if_fail (identifier != NULL, NULL);
	g_return_val_if_fail (data != NULL, NULL);

	return egg_asn1x_create_and_decode_full (defs, identifier, data, 0);
}

/* -----------------------------------------------------------------------------------
 * DUMPING and MESSAGES
 */

static void
dump_append_type (GString *output, gint type)
{
	#define XX(x) if (type == EGG_ASN1X_##x) g_string_append (output, #x " ")
	XX(CONSTANT); XX(IDENTIFIER); XX(INTEGER); XX(BOOLEAN); XX(SEQUENCE); XX(BIT_STRING);
	XX(OCTET_STRING); XX(TAG); XX(DEFAULT); XX(SIZE); XX(SEQUENCE_OF); XX(OBJECT_ID); XX(ANY);
	XX(SET); XX(SET_OF); XX(DEFINITIONS); XX(TIME); XX(UTC_TIME); XX(GENERALIZED_TIME); XX(CHOICE); XX(IMPORTS); XX(NULL);
	XX(ENUMERATED); XX(GENERAL_STRING); XX(NUMERIC_STRING); XX(IA5_STRING); XX(TELETEX_STRING);
	XX(PRINTABLE_STRING); XX(UNIVERSAL_STRING); XX(BMP_STRING); XX(UTF8_STRING); XX(VISIBLE_STRING);

	if (output->len == 0)
		g_string_printf (output, "%d ", (int)type);
	#undef XX
}

static void
dump_append_flags (GString *output, gint flags)
{
	#define XX(x) if ((FLAG_##x & flags) == FLAG_##x) g_string_append (output, #x " ")
	XX(UNIVERSAL); XX(PRIVATE); XX(APPLICATION); XX(EXPLICIT); XX(IMPLICIT); XX(TAG); XX(OPTION);
	XX(DEFAULT); XX(TRUE); XX(FALSE); XX(LIST); XX(MIN_MAX); XX(1_PARAM); XX(SIZE); XX(DEFINED_BY);
	XX(GENERALIZED); XX(UTC); XX(IMPORTS); XX(NOT_USED); XX(SET); XX(ASSIGN);
	/* XX(DOWN); XX(RIGHT); */
	#undef XX
}

static gboolean
traverse_and_dump (GNode *node, gpointer unused)
{
	EggAsn1xDef *def;
	guint i, depth;
	GString *output;
	gchar *string;
	Anode *an;
	GList *l;

	depth = g_node_depth (node);
	for (i = 0; i < depth - 1; ++i)
		g_print ("    ");

	an = node->data;
	output = g_string_new ("");
	dump_append_type (output, anode_def_type (node));
	dump_append_flags (output, anode_def_flags (node));
	string = g_utf8_casefold (output->str, output->len - 1);
	g_string_free (output, TRUE);
	g_print ("+ %s: %s [%s]%s\n", anode_def_name (node), anode_def_value (node),
	            string, an->parsed || an->value ? " *" : "");
	g_free (string);

	/* Print out all the options */
	for (l = an->opts; l; l = g_list_next (l)) {
		for (i = 0; i < depth; ++i)
			g_print ("    ");

		def = l->data;
		output = g_string_new ("");
		dump_append_type (output, def->type & 0xFF);
		dump_append_flags (output, def->type);
		string = g_utf8_casefold (output->str, output->len - 1);
		g_string_free (output, TRUE);
		g_print ("- %s: %s [%s]\n", def->name, (const gchar*)def->value, string);
		g_free (string);
	}

	return FALSE;
}

void
egg_asn1x_dump (GNode *asn)
{
	g_return_if_fail (asn);
	g_node_traverse (asn, G_PRE_ORDER, G_TRAVERSE_ALL, -1, traverse_and_dump, NULL);
}

static gboolean
traverse_and_get_failure (GNode *node, gpointer user_data)
{
	const gchar **failure = user_data;
	g_assert (!*failure);
	*failure = anode_failure_get (node);
	return (*failure != NULL);
}

const gchar*
egg_asn1x_message (GNode *asn)
{
	const gchar *failure = NULL;
	g_return_val_if_fail (asn, NULL);
	g_node_traverse (asn, G_POST_ORDER, G_TRAVERSE_ALL, -1, traverse_and_get_failure, &failure);
	return failure;
}

/* -----------------------------------------------------------------------------------
 * CLEARING and DESTROYING
 */

static gboolean
traverse_and_clear (GNode *node, gpointer unused)
{
	GNode *child, *next;
	gint type;

	anode_clear (node);

	type = anode_def_type (node);
	if (type == EGG_ASN1X_SET_OF || type == EGG_ASN1X_SEQUENCE_OF) {

		/* The first 'real' child is the template */
		child = node->children;
		g_return_val_if_fail (child, TRUE);

		/* And any others are extras */
		child = child->next;
		while (child) {
			next = child->next;
			anode_destroy (child);
			child = next;
		}
	}

	/* Don't stop traversal */
	return FALSE;
}

void
egg_asn1x_clear (GNode *asn)
{
	g_return_if_fail (asn);
	g_node_traverse (asn, G_POST_ORDER, G_TRAVERSE_ALL, -1, traverse_and_clear, NULL);
}

void
egg_asn1x_destroy (gpointer data)
{
	GNode *node = data;

	if (node != NULL) {
		g_return_if_fail (G_NODE_IS_ROOT (node));
		anode_destroy (node);
	}
}

/* --------------------------------------------------------------------------------
 * TIME PARSING
 */

glong
egg_asn1x_parse_time_general (const gchar *time, gssize n_time)
{
	gboolean ret;
	glong value;
	struct tm when;
	gint offset = 0;

	g_return_val_if_fail (time, -1);

	if (n_time < 0)
		n_time = strlen (time);

	ret = parse_general_time (time, n_time, &when, &offset);
	if (!ret)
		return -1;

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when.tm_year >= 2038) {
		value = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		value = timegm (&when);
		g_return_val_if_fail (*time >= 0, FALSE);
		value += offset;
	}

	return value;
}

glong
egg_asn1x_parse_time_utc (const gchar *time, gssize n_time)
{
	gboolean ret;
	glong value;
	struct tm when;
	gint offset = 0;

	g_return_val_if_fail (time, -1);

	if (n_time < 0)
		n_time = strlen (time);

	ret = parse_utc_time (time, n_time, &when, &offset);
	if (!ret)
		return -1;

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when.tm_year >= 2038) {
		value = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		value = timegm (&when);
		g_return_val_if_fail (*time >= 0, FALSE);
		value += offset;
	}

	return value;
}

/* --------------------------------------------------------------------------------
 * BASIC RAW ELEMENT INFO
 */

gssize
egg_asn1x_element_length (const guchar *data,
                          gsize n_data)
{
	guchar cls;
	int counter = 0;
	int cb, len;
	gulong tag;

	if (atlv_parse_cls_tag (data, data + n_data, &cls, &tag, &cb)) {
		counter += cb;
		len = atlv_parse_length (data + cb, data + n_data, &cb);
		counter += cb;
		if (len >= 0) {
			len += counter;
			if (n_data >= len)
				return len;
		}
	}

	return -1;
}

gconstpointer
egg_asn1x_element_content (const guchar *data,
                           gsize n_data,
                           gsize *n_content)
{
	int counter = 0;
	guchar cls;
	gulong tag;
	int cb, len;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (n_content != NULL, NULL);

	/* Now get the data out of this element */
	if (!atlv_parse_cls_tag (data, data + n_data, &cls, &tag, &cb))
		return NULL;

	counter += cb;
	len = atlv_parse_length (data + cb, data + n_data, &cb);
	if (len < 0)
		return NULL;
	counter += cb;

	*n_content = len;
	return (const guchar*)data + counter;
}
