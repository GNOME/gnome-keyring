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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg-asn1x.h"

#include <libtasn1.h>

#include <stdlib.h>
#include <string.h>

enum {
	NO_VALUE = 0,
	DER_VALUE,
	C_VALUE
};

/* From libtasn1's int.h */
enum {
	TYPE_CONSTANT = 1,
	TYPE_IDENTIFIER = 2,
	TYPE_INTEGER = 3,
	TYPE_BOOLEAN = 4,
	TYPE_SEQUENCE = 5,
	TYPE_BIT_STRING = 6,
	TYPE_OCTET_STRING = 7,
	TYPE_TAG = 8,
	TYPE_DEFAULT = 9,
	TYPE_SIZE = 10,
	TYPE_SEQUENCE_OF = 11,
	TYPE_OBJECT_ID = 12,
	TYPE_ANY = 13,
	TYPE_SET = 14,
	TYPE_SET_OF = 15,
	TYPE_DEFINITIONS = 16,
	TYPE_TIME = 17,
	TYPE_CHOICE = 18,
	TYPE_IMPORTS = 19,
	TYPE_NULL = 20,
	TYPE_ENUMERATED = 21,
	TYPE_GENERALSTRING = 27
};

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

typedef struct _Atlv {
	guchar cls;
	gulong tag;
	gint off;
	gint len;
	const guchar *buf;
	const guchar *end;
} Atlv;

typedef struct _Anode {
	const ASN1_ARRAY_TYPE *def;
	const ASN1_ARRAY_TYPE *join;
	Atlv *data;
} Anode;

/* TODO: Validate: LIST SIZE */

/* Forward Declarations */
static gboolean anode_decode_anything (GNode*, Atlv*);
static gboolean anode_decode_anything_for_flags (GNode *, Atlv*, gint);
static gboolean anode_validate_anything (GNode*);

static GNode*
anode_new (const ASN1_ARRAY_TYPE *def)
{
	Anode *an = g_slice_new0 (Anode);
	an->def = def;
	an->data = NULL;
	return g_node_new (an);
}

static void
anode_clear (GNode *node)
{
	Anode *an = node->data;
	if (an->data);
		g_slice_free (Atlv, an->data);
	an->data = NULL;
}

static gboolean
anode_free_func (GNode *node, gpointer unused)
{
	Anode *an = node->data;
	anode_clear (node);
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

static gpointer
anode_copy_func (gconstpointer src, gpointer unused)
{
	const Anode *san = src;
	Anode *an = g_slice_new0 (Anode);
	an->def = san->def;
	an->join = san->join;
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
	case TYPE_INTEGER:
	case TYPE_BOOLEAN:
	case TYPE_BIT_STRING:
	case TYPE_OCTET_STRING:
	case TYPE_OBJECT_ID:
	case TYPE_TIME:
	case TYPE_NULL:
	case TYPE_ENUMERATED:
	case TYPE_GENERALSTRING:
		return TRUE;
	case TYPE_SEQUENCE:
	case TYPE_SEQUENCE_OF:
	case TYPE_ANY:
	case TYPE_SET:
	case TYPE_SET_OF:
	case TYPE_CHOICE:
		return TRUE;
	case TYPE_CONSTANT:
	case TYPE_IDENTIFIER:
	case TYPE_TAG:
	case TYPE_DEFAULT:
	case TYPE_SIZE:
	case TYPE_DEFINITIONS:
	case TYPE_IMPORTS:
		return FALSE;
	default:
		g_return_val_if_reached (FALSE);
	}
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

static glong
anode_def_value_as_long (GNode *node)
{
	const gchar* value;
	gchar *end = NULL;
	gulong lval;

	value = anode_def_value (node);
	g_return_val_if_fail (value, G_MAXULONG);
	lval = strtol (value, &end, 10);
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

static GNode*
anode_child_with_type (GNode *node, gint type)
{
	GNode *child;

	for (child = node->children; child; child = child->next) {
		if (anode_def_type (child) == type)
			return child;
	}

	return NULL;
}

static GNode*
anode_next_with_type (GNode *node, gint type)
{
	for (node = node->next; node; node = node->next) {
		if (anode_def_type (node) == type)
			return node;
	}
	return NULL;
}

static GNode*
anode_child_with_real_type (GNode *node)
{
	GNode *child;

	for (child = node->children; child; child = child->next) {
		if (anode_def_type_is_real (child))
			return child;
	}

	return NULL;
}

static GNode*
anode_next_with_real_type (GNode *node)
{
	for (node = node->next; node; node = node->next) {
		if (anode_def_type_is_real (node))
			return node;
	}

	return NULL;
}

static gboolean
anode_def_size_value (GNode *node, const gchar *text, gulong *value)
{
	gchar *end = NULL;

	if (text == NULL) {
		*value = 0;
		return FALSE;
	} else if (g_str_equal (text, "MAX")) {
		*value = G_MAXULONG;
		return TRUE;
	} else if (g_ascii_isalpha (text[0])) {
		node = anode_child_with_name (node, text);
		g_return_val_if_fail (node, FALSE);
		return anode_def_size_value (node, anode_def_value (node), value);
	}

	*value = strtoul (text, &end, 10);
	g_return_val_if_fail (end && !end[0], FALSE);
	return TRUE;
}

static void
anode_set_tlv_data (GNode *node, Atlv *tlv)
{
	Anode *an = node->data;
	g_assert (!an->data);
	g_assert (tlv->len >= 0);
	an->data = g_slice_new0 (Atlv);
	memcpy (an->data, tlv, sizeof (Atlv));
}

static Atlv*
anode_get_tlv_data (GNode *node)
{
	Anode *an = node->data;
	return an->data;
}

static gulong
anode_encode_tag_for_flags (GNode *node, gint flags)
{
	GNode *child;
	gulong tag;

	g_return_val_if_fail (anode_def_type_is_real (node), G_MAXULONG);

	/* A context specific tag */
	if (flags & FLAG_TAG) {
		child = anode_child_with_type (node, TYPE_TAG);
		g_return_val_if_fail (child, G_MAXULONG);
		tag = anode_def_value_as_long (child);
		g_return_val_if_fail (tag >= 0, G_MAXULONG);
		return tag;
	}

	/* A tag from the universal set */
	switch (anode_def_type (node)) {
	case TYPE_INTEGER:
		return ASN1_TAG_INTEGER;
	case TYPE_ENUMERATED:
		return ASN1_TAG_ENUMERATED;
	case TYPE_BOOLEAN:
		return ASN1_TAG_BOOLEAN;
	case TYPE_BIT_STRING:
		return ASN1_TAG_BIT_STRING;
	case TYPE_OCTET_STRING:
		return ASN1_TAG_OCTET_STRING;
	case TYPE_OBJECT_ID:
		return ASN1_TAG_OBJECT_ID;
	case TYPE_NULL:
		return ASN1_TAG_NULL;
	case TYPE_GENERALSTRING:
		return ASN1_TAG_GENERALSTRING;
	case TYPE_TIME:
		if (flags & FLAG_GENERALIZED)
			return ASN1_TAG_GENERALIZEDTime;
		else if (flags & FLAG_UTC)
			return ASN1_TAG_UTCTime;
		else
			g_return_val_if_reached (G_MAXULONG);
	case TYPE_SEQUENCE:
	case TYPE_SEQUENCE_OF:
		return ASN1_TAG_SEQUENCE;
	case TYPE_SET:
	case TYPE_SET_OF:
		return ASN1_TAG_SET;

	/* These should be handled specially */
	case TYPE_ANY:
	case TYPE_CHOICE:
		return G_MAXULONG;

	/* These are not real nodes */
	case TYPE_CONSTANT:
	case TYPE_IDENTIFIER:
	case TYPE_TAG:
	case TYPE_DEFAULT:
	case TYPE_SIZE:
	case TYPE_DEFINITIONS:
	case TYPE_IMPORTS:
		g_return_val_if_reached (G_MAXULONG);

	/* Unknown value */
	default:
		g_return_val_if_reached (G_MAXULONG);
	}
}

static gulong
anode_encode_tag (GNode *node)
{
	return anode_encode_tag_for_flags (node, anode_def_flags (node));
}

static gboolean
anode_decode_cls_tag_len (const guchar *data, const guchar *end,
                          guchar *cls, gulong *tag, gint *off, gint *len)
{
	gint cb1, cb2;
	gint der_len;
	g_assert (end >= data);
	der_len = end - data;
	if (asn1_get_tag_der (data, der_len, cls, &cb1, tag) != ASN1_SUCCESS)
		return FALSE;
	*len = asn1_get_length_der (data + cb1, der_len - cb1, &cb2);
	if (*len < -1)
		return FALSE;
	*off = cb1 + cb2;
	if (*len >= 0 && data + *off + *len > end)
		return FALSE;
	return TRUE;
}

static gboolean
anode_check_indefinite_end (guchar cls, gulong tag, gint len)
{
	return (cls == ASN1_CLASS_UNIVERSAL && tag == 0 && len == 0);
}

static gboolean
anode_decode_indefinite_len (const guchar *data, const guchar *end, gint *rlen)
{
	gint result = 0;
	gint der_len;
	gint len;
	guchar cls;
	gulong tag;
	gint off;

	g_assert (data <= end);
	der_len = end - data;

	while (result < der_len) {
		if (!anode_decode_cls_tag_len (data + result, end, &cls, &tag, &off, &len))
			return FALSE;

		/* The indefinite end */
		if (anode_check_indefinite_end (cls, tag, len))
			break;

		result += off;

		/* Mid way check */
		if (result > der_len)
			break;

		if (len < 0) {
			if (!anode_decode_indefinite_len (data + result, end, &len))
				return FALSE;
			g_assert (len >= 0);
		}

		if (result + len > der_len)
			return FALSE;
		result += len;
	}

	if (result > der_len)
		return FALSE;
	*rlen = result;
	return TRUE;
}

static gboolean
anode_decode_tlv_for_data (const guchar *data, const guchar *end, Atlv *tlv)
{
	g_assert (data <= end);
	if (!anode_decode_cls_tag_len (data, end, &tlv->cls,
	                               &tlv->tag, &tlv->off, &tlv->len))
		return FALSE;
	tlv->buf = data;
	if (tlv->len < 0)
		tlv->end = end;
	else
		tlv->end = tlv->buf + tlv->len + tlv->off;
	g_assert (tlv->end <= end);
	return TRUE;
}

static gboolean
anode_decode_tlv_for_contents (Atlv *outer, gboolean first, Atlv *tlv)
{
	const guchar *data;
	const guchar *end;

	if (first) {
		data = outer->buf + outer->off;
		end = outer->end;
	} else {
		data = tlv->end;
		end = outer->end;
	}

	/* The end */
	if (end == data) {
		tlv->cls = ASN1_CLASS_UNIVERSAL;
		tlv->tag = 0;
		tlv->len = 0;
		tlv->off = 0;
		tlv->buf = data;
		tlv->end = end;
		return TRUE;
	}

	g_return_val_if_fail (end > data, FALSE);
	if (!anode_decode_tlv_for_data (data, end, tlv))
		return FALSE;

	/* Caller should stop before indefinite end, and not consume */
	if (anode_check_indefinite_end (tlv->cls, tlv->tag, tlv->len)) {
		tlv->buf = data;
		tlv->end = data;
		tlv->off = 0;
	}

	return TRUE;
}

static gboolean
anode_decode_choice (GNode *node, Atlv *tlv)
{
	GNode *child;

	for (child = anode_child_with_real_type (node);
	     child; child = anode_next_with_real_type (child)) {
		if (anode_decode_anything (child, tlv)) {
			anode_set_tlv_data (node, tlv);
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
anode_decode_struct_string (GNode *node, Atlv *outer)
{
	gint i = 0;
	Atlv tlv;

	/* Recalculated below */
	outer->len = 0;

	for (i = 0; TRUE; ++i) {
		if (!anode_decode_tlv_for_contents (outer, i == 0, &tlv))
			return FALSE;
		if (tlv.tag != outer->tag)
			return FALSE;
		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	anode_set_tlv_data (node, outer);
	return TRUE;
}

static gboolean
anode_decode_struct_any (GNode *node, Atlv *tlv)
{
	if (tlv->len < 0) {
		if (!anode_decode_indefinite_len (tlv->buf + tlv->off, tlv->end, &tlv->len))
			return FALSE;
		tlv->end = tlv->buf + tlv->off + tlv->len;
	}

	anode_set_tlv_data (node, tlv);
	return TRUE;
}

static gboolean
anode_decode_sequence_or_set (GNode *node, Atlv *outer)
{
	GNode *child;
	Atlv tlv;
	gint i;

	/* Recalculated below */
	outer->len = 0;

	/*
	 * The reason we can parse a set just like a sequence, is because in DER,
	 * the order of the SET is predefined by the tags. In addition the definitions
	 * we have are sorted.
	 */

	for (child = anode_child_with_real_type (node), i = 0;
	     child; child = anode_next_with_real_type (child), ++i) {

		if (!anode_decode_tlv_for_contents (outer, i == 0, &tlv))
			return FALSE;

		if (!anode_decode_anything (child, &tlv))
			return FALSE;

		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	anode_set_tlv_data (node, outer);
	return TRUE;
}

static gboolean
anode_decode_sequence_or_set_of (GNode *node, Atlv *outer)
{
	GNode *child, *copy;
	Atlv tlv;
	gint i;

	outer->len = 0;

	/* The one and only child */
	child = anode_child_with_real_type (node);
	g_return_val_if_fail (child, -1);

	/* Try to dig out as many of them as possible */
	for (i = 0; TRUE; ++i) {

		if (!anode_decode_tlv_for_contents (outer, i == 0, &tlv))
			return FALSE;

		/* The end of the road for us */
		if (tlv.off == 0)
			break;

		copy = anode_clone (child);
		if (!anode_decode_anything (copy, &tlv)) {
			anode_destroy (copy);
			return FALSE;
		}

		g_node_append (node, copy);
		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	anode_set_tlv_data (node, outer);
	return TRUE;
}

static gboolean
anode_decode_primitive (GNode *node, Atlv *tlv, gint flags)
{
	gint type;

	/* Must have a definite length */
	if (tlv->len < 0)
		return FALSE;

	type = anode_def_type (node);
	switch (type) {

	/* The primitive value types */
	case TYPE_INTEGER:
	case TYPE_ENUMERATED:
	case TYPE_BOOLEAN:
	case TYPE_BIT_STRING:
	case TYPE_OCTET_STRING:
	case TYPE_OBJECT_ID:
	case TYPE_NULL:
	case TYPE_GENERALSTRING:
	case TYPE_TIME:
		anode_set_tlv_data (node, tlv);
		return TRUE;

	/* Transparent types */
	case TYPE_ANY:
		anode_set_tlv_data (node, tlv);
		return TRUE;

	case TYPE_CHOICE:
		return anode_decode_choice (node, tlv);

	default:
		return FALSE;
	}

	g_assert_not_reached ();
}

static gboolean
anode_decode_structured (GNode *node, Atlv *tlv, gint flags)
{
	gboolean definite;
	const guchar *end;
	Atlv ctlv;
	gint len;
	gulong tag;
	guchar cls;
	gint off = 0;

	definite = (tlv->len >= 0);
	end = tlv->end;

	/* An explicit, wrapped tag */
	if (flags & FLAG_TAG && !(flags & FLAG_IMPLICIT)) {
		if (!anode_decode_tlv_for_contents (tlv, TRUE, &ctlv))
			return FALSE;
		flags &= ~FLAG_TAG;
		if (!anode_decode_anything_for_flags (node, &ctlv, flags))
			return FALSE;
		g_assert (ctlv.end >= ctlv.buf);
		tlv->len = ctlv.end - ctlv.buf;

	/* Other structured types */
	} else {
		switch (anode_def_type (node)) {
		case TYPE_ANY:
			if (!anode_decode_struct_any (node, tlv))
				return FALSE;
			break;
		case TYPE_CHOICE:
			if (!anode_decode_choice (node, tlv))
				return FALSE;
			break;
		case TYPE_GENERALSTRING:
		case TYPE_OCTET_STRING:
			if (!anode_decode_struct_string (node, tlv))
				return FALSE;
			break;
		case TYPE_SEQUENCE:
		case TYPE_SET:
			if (!anode_decode_sequence_or_set (node, tlv))
				return FALSE;
			break;
		case TYPE_SEQUENCE_OF:
		case TYPE_SET_OF:
			if (!anode_decode_sequence_or_set_of (node, tlv))
				return FALSE;
			break;
		default:
			return FALSE;
		}
	}

	g_return_val_if_fail (tlv->len >= 0, FALSE);

	/* Indefinite, needs to be terminated with zeros */
	if (!definite) {
		if (!anode_decode_cls_tag_len (tlv->buf + (tlv->off + tlv->len), end,
		                               &cls, &tag, &off, &len))
			return FALSE;
		if (!anode_check_indefinite_end (cls, tag, len))
			return FALSE;
		end = tlv->buf + tlv->off + tlv->len + off;
	}

	/* A structure must be filled up, no stuff ignored */
	if (tlv->buf + tlv->off + tlv->len + off != end)
		return FALSE;

	tlv->end = end;
	return TRUE;
}

static gboolean
anode_decode_anything_for_flags (GNode *node, Atlv *tlv, gint flags)
{
	gboolean ret;
	gulong tag;

	tag = anode_encode_tag_for_flags (node, flags);

	/* We don't know what the tag is supposed to be */
	if (tag == G_MAXULONG)
		tag = tlv->tag;

	/* Tag does not match, what do we do? */
	if (tlv->off == 0 || tag != tlv->tag) {
		if (flags & FLAG_OPTION || flags & FLAG_DEFAULT) {
			tlv->len = 0;
			tlv->end = tlv->buf;
			tlv->off = 0;
			return TRUE;
		} else {
			return FALSE;
		}
	}

	/* Structured value */
	if (tlv->cls & ASN1_CLASS_STRUCTURED)
		ret = anode_decode_structured (node, tlv, flags);

	/* A primitive simple value */
	else
		ret = anode_decode_primitive (node, tlv, flags);

	return ret;
}

static gboolean
anode_decode_anything (GNode *node, Atlv *tlv)
{
	return anode_decode_anything_for_flags (node, tlv, anode_def_flags (node));
}

gboolean
egg_asn1x_decode (GNode *asn, gconstpointer data, gsize n_data)
{
	Atlv tlv;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	egg_asn1x_clear (asn);

	if (!anode_decode_tlv_for_data (data, (const guchar*)data + n_data, &tlv))
		return FALSE;

	if (!anode_decode_anything (asn, &tlv))
		return FALSE;

	return egg_asn1x_validate (asn);
}

/* -----------------------------------------------------------------------------------
 * READing
 */

static int
atoin (const char *p, int digits)
{
	int ret = 0, base = 1;
	while(--digits >= 0) {
		if (p[digits] < '0' || p[digits] > '9')
			return -1;
		ret += (p[digits] - '0') * base;
		base *= 10;
	}
	return ret;
}

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

#ifndef HAVE_TIMEGM
time_t timegm(struct tm *t)
{
	time_t tl, tb;
	struct tm *tg;

	tl = mktime (t);
	if (tl == -1)
	{
		t->tm_hour--;
		tl = mktime (t);
		if (tl == -1)
			return -1; /* can't deal with output from strptime */
		tl += 3600;
	}
	tg = gmtime (&tl);
	tg->tm_isdst = 0;
	tb = mktime (tg);
	if (tb == -1)
	{
		tg->tm_hour--;
		tb = mktime (tg);
		if (tb == -1)
			return -1; /* can't deal with output from gmtime */
		tb += 3600;
	}
	return (tl - (tb - tl));
}
#endif // NOT_HAVE_TIMEGM

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
anode_read_time (GNode *node, Atlv *tlv, time_t *value)
{
	const gchar *data;
	gboolean ret;
	struct tm when;
	gint offset;
	gint flags;

	flags = anode_def_flags (node);
	data = (gchar*)(tlv->buf + tlv->off);

	if (flags & FLAG_GENERALIZED)
		ret = parse_general_time (data, tlv->len, &when, &offset);
	else if (flags & FLAG_UTC)
		ret = parse_utc_time (data, tlv->len, &when, &offset);
	else
		g_return_val_if_reached (FALSE);

	if (!ret)
		return FALSE;

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when.tm_year >= 2038) {
		*value = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		*value = timegm (&when);
		if (*time < 0)
			return FALSE;
		*value += offset;
	}

	return TRUE;
}

static gboolean
anode_read_integer_as_long (GNode *node, Atlv *tlv, glong *value)
{
	const guchar *p;
	gsize k;

	if (tlv->len < 1 || tlv->len > 4)
		return FALSE;

	p = tlv->buf + tlv->off;
	*value = 0;
	for (k = 0; k < tlv->len; ++k)
		*value |= p[k] << (8 * ((tlv->len - 1) - k));

	return TRUE;
}

static gboolean
anode_read_string (GNode *node, Atlv *tlv, gpointer value, gsize *n_value)
{
	Atlv ctlv;
	guchar *buf;
	gint n_buf;
	gint i;

	g_assert (tlv);
	g_assert (n_value);

	buf = value;
	n_buf = *n_value;

	/* Is it constructed ? */
	if (tlv->cls & ASN1_CLASS_STRUCTURED) {
		*n_value = 0;
		for (i = 0; TRUE; ++i) {
			if (!anode_decode_tlv_for_contents (tlv, i == 0, &ctlv))
				return FALSE;
			if (ctlv.off == 0)
				break;
			if (ctlv.cls & ASN1_CLASS_STRUCTURED)
				return FALSE;
			*n_value += ctlv.len;
			if (buf) {
				if (n_buf >= ctlv.len)
					memcpy (buf, ctlv.buf + ctlv.off, ctlv.len);
				buf += ctlv.len;
				n_buf -= ctlv.len;
			}
		}
		if (n_buf < 0)
			return FALSE;

	/* Primitive, just return the contents */
	} else {
		*n_value = tlv->len;
		if (buf) {
			if (n_buf < tlv->len)
				return FALSE;
			memcpy (buf, tlv->buf + tlv->off, tlv->len);
		}
	}

	return TRUE;
}

/* -----------------------------------------------------------------------------------
 * VALIDATION
 */

static gboolean
anode_validate_size (GNode *node, gulong length)
{
	GNode *size;
	gulong value1 = 0;
	gulong value2 = G_MAXULONG;

	if (anode_def_flags (node) & FLAG_SIZE) {
		size = anode_child_with_type (node, TYPE_SIZE);
		g_return_val_if_fail (size, FALSE);
		if (!anode_def_size_value (size, anode_def_value (size), &value1))
			g_return_val_if_reached (FALSE);
		if (anode_def_flags (size) & FLAG_MIN_MAX) {
			if (!anode_def_size_value (size, anode_def_name (size), &value2))
				g_return_val_if_reached (FALSE);
			if (length < value1 || length >= value2)
				return FALSE;
		} else {
			if (length != value1)
				return FALSE;
		}
	}

	return TRUE;
}

static gboolean
anode_validate_integer (GNode *node, Atlv *tlv)
{
	glong value, check;
	gboolean found;
	GNode *child;
	gint flags;

	g_assert (tlv);

	/* Integers must be at least one byte long */
	if (tlv->len <= 0)
		return FALSE;

	flags = anode_def_flags (node);
	if (flags & FLAG_LIST) {
		/* Parse out the value, we only support small integers*/
		if (!anode_read_integer_as_long (node, tlv, &value))
			return FALSE;

		/* Look through the list of constants */
		found = FALSE;
		for (child = anode_child_with_type (node, TYPE_CONSTANT);
		     child; child = anode_next_with_type (child, TYPE_CONSTANT)) {
			check = anode_def_value_as_long (child);
			g_return_val_if_fail (check != G_MAXULONG, FALSE);
			if (check == value) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}

	return TRUE;
}

static gboolean
anode_validate_enumerated (GNode *node, Atlv *tlv)
{
	g_assert (tlv);

	if (!anode_validate_integer (node, tlv))
		return FALSE;
	g_assert (tlv->len); /* Checked above */
	/* Enumerated must be positive */
	if (tlv->buf[tlv->off] & 0x80)
		return FALSE;
	return TRUE;
}

static gboolean
anode_validate_boolean (GNode *node, Atlv *tlv)
{
	g_assert (tlv);

	/* Must one byte, and zero or all ones */
	if (tlv->len != 1)
		return FALSE;
	if (tlv->buf[tlv->off] != 0x00 && tlv->buf[tlv->off] != 0xFF)
		return FALSE;
	return TRUE;
}

static gboolean
anode_validate_bit_string (GNode *node, Atlv *tlv)
{
	guchar empty, mask;
	g_assert (tlv);

	/* At least two bytes in length */
	if (tlv->len < 2)
		return FALSE;
	/* First byte is the number of free bits at end */
	empty = tlv->buf[tlv->off];
	if (empty > 7)
		return FALSE;
	/* Free octets at end must be zero */
	mask = 0xFF >> (8 - empty);
	if (tlv->buf[tlv->off + tlv->len - 1] & mask)
		return FALSE;
	return TRUE;
}

static gboolean
anode_validate_string (GNode *node, Atlv *tlv)
{
	gsize length;

	if (!anode_read_string (node, tlv, NULL, &length))
		return FALSE;

	return anode_validate_size (node, (gulong)length);
}

static gboolean
anode_validate_object_id (GNode *node, Atlv *tlv)
{
	const guchar *p;
	gboolean lead;
	guint val, pval;
	gint k;

	g_assert (tlv);
	if (tlv->len <= 0)
		return FALSE;
	p = tlv->buf + tlv->off;

	/* TODO: Validate first byte? */
	for (k = 1, lead = 1, val = 0, pval = 0; k < tlv->len; ++k) {
		/* X.690: the leading byte must never be 0x80 */
		if (lead && p[k] == 0x80)
			return FALSE;
		val = val << 7;
		val |= p[k] & 0x7F;
		/* Check for wrap around */
		if (val < pval)
			return FALSE;
		pval = val;
		if (!(p[k] & 0x80)) {
			pval = val = 0;
			lead = 1;
		}
	}

	return TRUE;
}

static gboolean
anode_validate_null (GNode *node, Atlv *tlv)
{
	g_assert (tlv);
	return (tlv->len == 0);
}

static gboolean
anode_validate_time (GNode *node, Atlv *tlv)
{
	glong time;
	return anode_read_time (node, tlv, &time);
}

static gboolean
anode_validate_choice (GNode *node)
{
	gboolean have = FALSE;
	GNode *child;

	/* One and only one of the children must be set */
	for (child = anode_child_with_real_type (node);
	     child; child = anode_next_with_real_type (child)) {
		if (anode_get_tlv_data (child)) {
			if (have)
				return FALSE;
			have = TRUE;
			if (!anode_validate_anything (child))
				return FALSE;
		}
	}

	return have;
}

static gboolean
anode_validate_sequence_or_set (GNode *node)
{
	GNode *child;

	/* All of the children must validate properly */
	for (child = anode_child_with_real_type (node);
	     child; child = anode_next_with_real_type (child)) {
		if (!anode_validate_anything (child))
			return FALSE;
	}

	return TRUE;
}

static gboolean
anode_validate_sequence_or_set_of (GNode *node)
{
	GNode *child;
	Atlv *tlv;
	gulong tag;
	gulong count;

	/* The first one must be empty */
	child = anode_child_with_real_type (node);
	g_return_val_if_fail (child, FALSE);
	g_return_val_if_fail (!anode_get_tlv_data (child), FALSE);

	tag = anode_encode_tag (child);

	/* All of the other children must validate properly */
	for (child = anode_next_with_real_type (child);
	     child; child = anode_next_with_real_type (child)) {
		if (!anode_validate_anything (child))
			return FALSE;

		/* Must have same tag as the top */
		if (tag != G_MAXULONG) {
			tlv = anode_get_tlv_data (child);
			g_return_val_if_fail (tlv, FALSE);
			if (tlv->tag != tag)
				return FALSE;
		}

		++count;
	}

	return anode_validate_size (node, count);
}

static gboolean
anode_validate_anything (GNode *node)
{
	Atlv *tlv;
	gint type;

	type = anode_def_type (node);
	tlv = anode_get_tlv_data (node);

	if (!tlv) {
		if (anode_def_flags (node) & FLAG_OPTION)
			return TRUE;
		return FALSE;
	}

	switch (type) {

	/* The primitive value types */
	case TYPE_INTEGER:
		return anode_validate_integer (node, tlv);
	case TYPE_ENUMERATED:
		return anode_validate_enumerated (node, tlv);
	case TYPE_BOOLEAN:
		return anode_validate_boolean (node, tlv);
	case TYPE_BIT_STRING:
		return anode_validate_bit_string (node, tlv);
	case TYPE_OCTET_STRING:
		return anode_validate_string (node, tlv);
	case TYPE_OBJECT_ID:
		return anode_validate_object_id (node, tlv);
	case TYPE_NULL:
		return anode_validate_null (node, tlv);
	case TYPE_GENERALSTRING:
		return anode_validate_string (node, tlv);
	case TYPE_TIME:
		return anode_validate_time (node, tlv);

	/* Transparent types */
	case TYPE_ANY:
		return TRUE;
	case TYPE_CHOICE:
		return anode_validate_choice (node);

	/* Structured types */
	case TYPE_SEQUENCE:
	case TYPE_SET:
		return anode_validate_sequence_or_set (node);

	case TYPE_SEQUENCE_OF:
	case TYPE_SET_OF:
		return anode_validate_sequence_or_set_of (node);

	default:
		g_return_val_if_reached (FALSE);
	}
}

gboolean
egg_asn1x_validate (GNode *asn)
{
	g_return_val_if_fail (asn, FALSE);
	return anode_validate_anything (asn);
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

	taga = anode_encode_tag (na);
	g_return_val_if_fail (taga != G_MAXULONG, 0);

	tagb = anode_encode_tag (nb);
	g_return_val_if_fail (tagb != G_MAXULONG, 0);

	if (taga == tagb)
		return 0;
	return (taga < tagb) ? -1 : 1;
}

static void
join_each_child (GNode *child, gpointer data)
{
	GNode *node = data;
	g_node_unlink (child);
	g_node_append (node, child);
}

static GNode*
lookup_type_node (const ASN1_ARRAY_TYPE *defs, const gchar *identifier, gint type)
{
	/* Find the one we're interested in */
	while (defs && (defs->value || defs->type || defs->name)) {
		if ((defs->type & 0xFF) == type &&
		    defs->name && g_str_equal (identifier, defs->name))
			return anode_new (defs);
		++defs;
	}

	return NULL;
}

static gboolean
traverse_and_prepare (GNode *node, gpointer data)
{
	const ASN1_ARRAY_TYPE *defs = data;
	const gchar *identifier;
	Anode *an, *anj;
	GNode *join = NULL;
	GNode *child, *next;
	GList *list = NULL, *l;

	/* A while, because the stuff we join, could also be an identifier */
	while (anode_def_type (node) == TYPE_IDENTIFIER) {
		an = node->data;
		identifier = an->join ? an->join->value : an->def->value;
		g_return_val_if_fail (identifier, TRUE);
		egg_asn1x_destroy (join);
		join = egg_asn1x_create (defs, identifier);
		g_return_val_if_fail (join, TRUE);
		anj = join->data;
		an->join = anj->def;
	}

	if (join) {
		g_node_children_foreach (join, G_TRAVERSE_ALL, join_each_child, node);
		egg_asn1x_destroy (join);
	}

	/* Lookup the max set size */
	if (anode_def_type (node) == TYPE_SIZE) {
		identifier = anode_def_name (node);
		if (identifier && !g_str_equal (identifier, "MAX") &&
		    g_ascii_isalpha (identifier[0])) {
			join = lookup_type_node (defs, identifier, TYPE_INTEGER);
			g_return_val_if_fail (join, TRUE);
			g_node_append (node, join);
		}
	}

	/* Sort the children of any sets */
	if (anode_def_type (node) == TYPE_SET) {
		child = node->children;
		while (child) {
			next = child->next;
			if (anode_def_type_is_real (child)) {
				g_node_unlink (child);
				list = g_list_prepend (list, child);
			}
			child = next;
		}
		list = g_list_sort (list, compare_nodes_by_tag);
		for (l = list; l; l = g_list_next (l))
			g_node_append (node, l->data);
		g_list_free (list);
	}

	/* Continue traversal */
	return FALSE;
}

GNode*
egg_asn1x_create (const ASN1_ARRAY_TYPE *defs, const gchar *identifier)
{
	const ASN1_ARRAY_TYPE *def;
	GNode *root, *parent, *node;
	int flags;

	g_return_val_if_fail (defs, NULL);
	g_return_val_if_fail (identifier, NULL);

	def = defs;

	/* Find the one we're interested in */
	while (def && (def->value || def->type || def->name)) {
		if (def->name && g_str_equal (identifier, def->name))
			break;
		++def;
	}

	if (!def->name || !def->type)
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

/* -----------------------------------------------------------------------------------
 * DUMPING
 */

static gboolean
traverse_and_dump (GNode *node, gpointer unused)
{
	guint i, depth;
	GString *output;
	gchar *string;
	int flags;
	int type;

	depth = g_node_depth (node);
	for (i = 0; i < depth - 1; ++i)
		g_printerr ("    ");

	output = g_string_new ("");

	/* Figure out the type */
	type = anode_def_type (node);
	#define XX(x) if (type == TYPE_##x) g_string_append (output, #x " ")
	XX(CONSTANT); XX(IDENTIFIER); XX(INTEGER); XX(BOOLEAN); XX(SEQUENCE); XX(BIT_STRING);
	XX(OCTET_STRING); XX(TAG); XX(DEFAULT); XX(SIZE); XX(SEQUENCE_OF); XX(OBJECT_ID); XX(ANY);
	XX(SET); XX(SET_OF); XX(DEFINITIONS); XX(TIME); XX(CHOICE); XX(IMPORTS); XX(NULL);
	XX(ENUMERATED); XX(GENERALSTRING);
	if (output->len == 0)
		g_string_printf (output, "%d ", (int)type);
	#undef XX

	/* Figure out the flags */
	flags = anode_def_flags (node);
	#define XX(x) if ((FLAG_##x & flags) == FLAG_##x) g_string_append (output, #x " ")
	XX(UNIVERSAL); XX(PRIVATE); XX(APPLICATION); XX(EXPLICIT); XX(IMPLICIT); XX(TAG); XX(OPTION);
	XX(DEFAULT); XX(TRUE); XX(FALSE); XX(LIST); XX(MIN_MAX); XX(1_PARAM); XX(SIZE); XX(DEFINED_BY);
	XX(GENERALIZED); XX(UTC); XX(IMPORTS); XX(NOT_USED); XX(SET); XX(ASSIGN);
	/* XX(DOWN); XX(RIGHT); */
	#undef XX

	string = g_utf8_casefold (output->str, output->len - 1);
	g_string_free (output, TRUE);
	g_printerr ("%s: %s [%s]\n", anode_def_name (node), anode_def_value (node), string);
	g_free (string);
	return FALSE;
}

void
egg_asn1x_dump (GNode *asn)
{
	g_return_if_fail (asn);
	g_node_traverse (asn, G_PRE_ORDER, G_TRAVERSE_ALL, -1, traverse_and_dump, NULL);
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
	if (type == TYPE_SET_OF || type == TYPE_SEQUENCE_OF) {

		/* The first 'real' child is the template */
		child = anode_child_with_real_type (node);
		g_return_val_if_fail (child, TRUE);

		/* And any others are extras */
		child = anode_next_with_real_type (child);
		while (child) {
			next = anode_next_with_real_type (child);
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
	if (data)
		anode_destroy (data);
}
