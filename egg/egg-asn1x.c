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

typedef struct _Aenc Aenc;
typedef struct _Atlv Atlv;
typedef struct _Anode Anode;
typedef struct _Abuf Abuf;

struct _Aenc {
	EggAsn1xEncoder encoder;
	gpointer user_data;
	GDestroyNotify destroy;
};

struct _Atlv {
	guchar cls;
	gulong tag;
	gint off;
	gint oft;
	gint len;
	const guchar *buf;
	const guchar *end;
};

struct _Anode {
	const ASN1_ARRAY_TYPE *def;
	const ASN1_ARRAY_TYPE *join;
	GList *opts;
	Atlv *tlv;
	Aenc *enc;
	gchar* failure;
};

struct _Abuf {
	guchar* data;
	gsize n_data;
	gpointer user_data;
};

/* Forward Declarations */
static gboolean anode_decode_anything (GNode*, Atlv*);
static gboolean anode_decode_anything_for_flags (GNode *, Atlv*, gint);
static gboolean anode_validate_anything (GNode*);
static gboolean anode_encode_prepare (GNode*);

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

static GNode*
anode_new (const ASN1_ARRAY_TYPE *def)
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

static gulong
anode_def_value_as_ulong (ASN1_ARRAY_TYPE *def)
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
anode_opt_add (GNode *node, const ASN1_ARRAY_TYPE *def)
{
	Anode *an = node->data;
	an->opts = g_list_append (an->opts, (gpointer)def);
}

static ASN1_ARRAY_TYPE*
anode_opt_lookup (GNode *node, gint type, const gchar *name)
{
	Anode *an = node->data;
	ASN1_ARRAY_TYPE* def;
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

static GList*
anode_opts_lookup (GNode *node, gint type, const gchar *name)
{
	Anode *an = node->data;
	ASN1_ARRAY_TYPE* def;
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

static gint
compare_tlvs (Atlv *tlva, Atlv *tlvb)
{
	gint la = tlva->off + tlva->len;
	gint lb = tlvb->off + tlvb->len;
	gint res;

	g_assert (tlva->buf);
	g_assert (tlvb->buf);
	res = memcmp (tlva->buf, tlvb->buf, MIN (la, lb));
	if (la == lb || res != 0)
		return res;
	return la < lb ? -1 : 1;
}

static void
anode_set_tlv_data (GNode *node, Atlv *tlv)
{
	Anode *an = node->data;
	g_assert (!an->tlv);
	g_assert (tlv->len >= 0);
	an->tlv = g_slice_new0 (Atlv);
	memcpy (an->tlv, tlv, sizeof (Atlv));
}

static Atlv*
anode_get_tlv_data (GNode *node)
{
	Anode *an = node->data;
	return an->tlv;
}

static void
anode_clr_tlv_data (GNode *node)
{
	Anode *an = node->data;
	if (an->tlv);
		g_slice_free (Atlv, an->tlv);
	an->tlv = NULL;
}

static void
anode_clr_enc_data (GNode *node)
{
	Anode *an = node->data;
	if (an->enc) {
		if (an->enc->destroy)
			(an->enc->destroy) (an->enc->user_data);
		g_slice_free (Aenc, an->enc);
		an->enc = NULL;
	}
}

static void
anode_set_enc_data (GNode *node, EggAsn1xEncoder encoder,
                    gpointer user_data, GDestroyNotify destroy)
{
	Anode *an = node->data;
	g_assert (!an->enc);
	an->enc = g_slice_new0 (Aenc);
	an->enc->encoder = encoder;
	an->enc->user_data = user_data;
	an->enc->destroy = destroy;
}

static Aenc*
anode_get_enc_data (GNode *node)
{
	Anode *an = node->data;
	return an->enc;
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
	return FALSE; /* So this can be changed */
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
	anode_clr_tlv_data (node);
	anode_clr_enc_data (node);
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
	ASN1_ARRAY_TYPE *def;

	/* A context specific tag */
	if (flags & FLAG_TAG) {
		def = anode_opt_lookup (node, TYPE_TAG, NULL);
		g_return_val_if_fail (def, G_MAXULONG);
		return anode_def_value_as_ulong (def);
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
anode_calc_tag (GNode *node)
{
	return anode_calc_tag_for_flags (node, anode_def_flags (node));
}

/* -------------------------------------------------------------------------
 * DECODE
 */

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

	for (child = node->children; child; child = child->next) {
		if (anode_decode_anything (child, tlv))
			return TRUE;
	}

	return anode_failure (node, "no choice is present");
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
			return anode_failure (node, "invalid encoding of child");
		if (tlv.tag != outer->tag)
			return anode_failure (node, "contents have an invalid tag");
		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	return TRUE;
}

static gboolean
anode_decode_struct_any (GNode *node, Atlv *tlv)
{
	if (tlv->len < 0) {
		if (!anode_decode_indefinite_len (tlv->buf + tlv->off, tlv->end, &tlv->len))
			return anode_failure (node, "could not find end of encoding");
		tlv->end = tlv->buf + tlv->off + tlv->len;
	}

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

	for (child = node->children, i = 0; child; child = child->next, ++i) {

		if (!anode_decode_tlv_for_contents (outer, i == 0, &tlv))
			return anode_failure (node, "invalid encoding of child");

		if (!anode_decode_anything (child, &tlv))
			return FALSE;

		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	return TRUE;
}

static gboolean
anode_decode_sequence_or_set_of (GNode *node, Atlv *outer)
{
	GNode *child, *other;
	Atlv tlv;
	gint i;

	outer->len = 0;

	/* The first child */
	child = node->children;
	g_return_val_if_fail (child, FALSE);

	/* Remove all the other children */
	while (child->next)
		anode_destroy (child->next);

	/* Try to dig out as many of them as possible */
	for (i = 0; TRUE; ++i) {

		if (!anode_decode_tlv_for_contents (outer, i == 0, &tlv))
			return anode_failure (node, "invalid encoding of child");

		/* The end of the road for us */
		if (tlv.off == 0)
			break;

		if (i == 0) {
			other = child;
		} else {
			other = anode_clone (child);
			g_node_append (node, other);
		}

		if (!anode_decode_anything (other, &tlv))
			return FALSE;

		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
	return TRUE;
}

static gboolean
anode_decode_primitive (GNode *node, Atlv *tlv, gint flags)
{
	gint type;

	/* Must have a definite length */
	if (tlv->len < 0)
		return anode_failure (node, "primitive value with an indefinite length");

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
		if (!anode_decode_choice (node, tlv))
			return FALSE;
		anode_set_tlv_data (node, tlv);
		return TRUE;

	default:
		return anode_failure (node, "primitive value of an unexpected type");
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
		if ((tlv->cls & ASN1_CLASS_CONTEXT_SPECIFIC) == 0)
			return anode_failure (node, "missing context specific tag");
		if (!anode_decode_tlv_for_contents (tlv, TRUE, &ctlv))
			return anode_failure (node, "invalid encoding of child");
		flags &= ~FLAG_TAG;
		if (!anode_decode_anything_for_flags (node, &ctlv, flags))
			return FALSE;

		/* Use most of the child's tlv */
		tlv->cls = ctlv.cls;
		tlv->tag = ctlv.tag;
		tlv->off += ctlv.off;
		tlv->oft = ctlv.off;
		tlv->len = ctlv.len;
		anode_clr_tlv_data (node);

	/* Other structured types */
	} else {
		if ((tlv->cls & ASN1_CLASS_CONTEXT_SPECIFIC) != 0)
			return anode_failure (node, "invalid context specific tag");
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
			return anode_failure (node, "end of indefinite content is missing");
		if (!anode_check_indefinite_end (cls, tag, len))
			return anode_failure (node, "end of indefinite content is invalid");
		end = tlv->buf + tlv->off + tlv->len + off;
	}

	/* A structure must be filled up, no stuff ignored */
	if (tlv->buf + tlv->off + tlv->len + off < end)
		return anode_failure (node, "extra data at the end of the content");
	g_return_val_if_fail (tlv->buf + tlv->off + tlv->len + off == end, FALSE);

	tlv->end = end;
	anode_set_tlv_data (node, tlv);
	return TRUE;
}

static gboolean
anode_decode_anything_for_flags (GNode *node, Atlv *tlv, gint flags)
{
	gboolean ret;
	gulong tag;

	tag = anode_calc_tag_for_flags (node, flags);

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
		return anode_failure (asn, "content is not encoded properly");

	if (!anode_decode_anything (asn, &tlv))
		return FALSE;

	return egg_asn1x_validate (asn);
}

/* -----------------------------------------------------------------------------------
 * ENCODING
 */

static gint
anode_encode_cls_tag_len (guchar *data, gsize n_data, guchar cls,
                          gulong tag, gint len)
{
	guchar temp[sizeof(gulong)];
	gint length;
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
	length = n_data - off;
	asn1_length_der (len, data ? data + off : NULL, &length);
	off += length;

	g_assert (!data || n_data >= off);
	return off;
}

static void
anode_encode_tlv_and_enc (GNode *node, gsize n_data, EggAsn1xEncoder encoder,
                          gpointer user_data, GDestroyNotify destroy)
{
	gboolean explicit = FALSE;
	gulong tag;
	gint flags;
	Atlv tlv;

	g_assert (node);
	g_assert (encoder);

	/* The data length */
	memset (&tlv, 0, sizeof (tlv));
	tlv.len = n_data;

	/* Figure out the basis if the class */
	switch (anode_def_type (node)) {
	case TYPE_INTEGER:
	case TYPE_BOOLEAN:
	case TYPE_BIT_STRING:
	case TYPE_OCTET_STRING:
	case TYPE_OBJECT_ID:
	case TYPE_TIME:
	case TYPE_ENUMERATED:
	case TYPE_GENERALSTRING:
		tlv.cls = ASN1_CLASS_UNIVERSAL;
		break;
	/* Container types */
	case TYPE_SEQUENCE:
	case TYPE_SET:
	case TYPE_SEQUENCE_OF:
	case TYPE_SET_OF:
		tlv.cls = (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL);
		break;

	/* Transparent types shouldn't get here */
	case TYPE_ANY:
	case TYPE_CHOICE:
		g_return_if_reached ();

	default:
		g_return_if_reached ();
	};

	/* Build up the class */
	flags = anode_def_flags (node);
	if (flags & FLAG_TAG) {
		explicit = !(flags & FLAG_IMPLICIT);
		if (explicit)
			flags &= ~FLAG_TAG;
		else
			tlv.cls |= ASN1_CLASS_CONTEXT_SPECIFIC;
	}

	/* And now the tag */
	tlv.tag = anode_calc_tag_for_flags (node, flags);

	/* Calculate the length for the main thingy */
	tlv.off = anode_encode_cls_tag_len (NULL, 0, tlv.cls, tlv.tag, tlv.len);

	/* Wrap that in another explicit tag if necessary */
	if (explicit) {
		tag = anode_calc_tag (node);
		g_return_if_fail (tag != G_MAXULONG);
		tlv.oft = anode_encode_cls_tag_len (NULL, 0, 0, tag, tlv.off + tlv.len);
		tlv.off += tlv.oft;
	}

	/* Not completely filled in */
	tlv.buf = tlv.end = 0;

	anode_clear (node);
	anode_set_tlv_data (node, &tlv);
	anode_set_enc_data (node, encoder, user_data, destroy);
}

static gboolean
anode_encode_build (GNode *node, guchar *data, gsize n_data)
{
	gint type;
	gint flags;
	guchar cls;
	gulong tag;
	Aenc *enc;
	Atlv *tlv;
	gint off = 0;

	type = anode_def_type (node);
	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, FALSE);

	/* Should have an encoder */
	enc = anode_get_enc_data (node);
	g_return_val_if_fail (enc, FALSE);

	/* Encode any explicit tag */
	flags = anode_def_flags (node);
	if (flags & FLAG_TAG && !(flags & FLAG_IMPLICIT)) {
		tag = anode_calc_tag (node);
		g_return_val_if_fail (tag != G_MAXULONG, FALSE);
		cls = (ASN1_CLASS_STRUCTURED | ASN1_CLASS_CONTEXT_SPECIFIC);
		g_assert (tlv->oft > 0 && tlv->oft < tlv->off);
		off = anode_encode_cls_tag_len (data, n_data, cls, tag, (tlv->off - tlv->oft) + tlv->len);
		g_assert (off == tlv->oft);
	}

	/* Now encode the main tag */
	off += anode_encode_cls_tag_len (data + off, n_data - off, tlv->cls, tlv->tag, tlv->len);
	g_assert (off == tlv->off);

	/* Setup the remainder of the tlv */
	g_assert (tlv->len + tlv->off == n_data);
	tlv->buf = data;
	tlv->end = data + n_data;

	/* Encode in the data */
	if (!(enc->encoder) (enc->user_data, data + tlv->off, tlv->len))
		return FALSE;

	return TRUE;
}

static void
anode_encode_rollback (GNode *node)
{
	GNode *child;
	Aenc *enc;
	Atlv *tlv;

	/* Undo any references to our new buffer */
	enc = anode_get_enc_data (node);
	if (enc) {
		tlv = anode_get_tlv_data (node);
		g_return_if_fail (tlv);
		tlv->buf = tlv->end = NULL;
	}

	for (child = node->children; child; child = child->next)
		anode_encode_rollback (child);
}

static void
anode_encode_commit (GNode *node)
{
	GNode *child;

	/* Remove and free all the encoder stuff */
	anode_clr_enc_data (node);

	for (child = node->children; child; child = child->next)
		anode_encode_commit (child);
}

static gint
compare_bufs (gconstpointer a, gconstpointer b)
{
	const Abuf *ba = a;
	const Abuf *bb = b;
	gint res = memcmp (ba->data, bb->data, MIN (ba->n_data, bb->n_data));
	if (ba->n_data == bb->n_data || res != 0)
		return res;
	return ba->n_data < bb->n_data ? -1 : 1;
}

static gboolean
traverse_and_sort_set_of (GNode *node, gpointer user_data)
{
	EggAllocator allocator = user_data;
	GList *bufs, *l;
	Abuf *buf;
	guchar *data;
	gsize n_data;
	Atlv *tlv;
	GNode *child;

	/* We have to sort any SET OF :( */
	if (anode_def_type (node) != TYPE_SET_OF)
		return FALSE;

	bufs = NULL;
	for (child = node->children; child; child = child->next) {
		tlv = anode_get_tlv_data (child);
		if (!tlv)
			continue;

		/* Allocate enough memory */
		n_data = tlv->len + tlv->off;
		data = (allocator) (NULL, n_data + 1);
		if (!data)
			break;

		if (!anode_encode_build (child, data, n_data)) {
			(allocator) (data, 0);
			continue;
		}

		buf = g_slice_new0 (Abuf);
		buf->user_data = child;
		buf->n_data = n_data;
		buf->data = data;
		bufs = g_list_prepend (bufs, buf);
		g_node_unlink (child);
	}

	bufs = g_list_sort (bufs, compare_bufs);

	for (l = bufs; l; l = g_list_next (l)) {
		buf = l->data;
		g_node_append (node, buf->user_data);
		(allocator) (buf->data, 0);
		g_slice_free (Abuf, buf);
	}

	anode_encode_rollback (node);
	g_list_free (bufs);
	return FALSE;
}

static gboolean
anode_encoder_simple (gpointer user_data, guchar *data, gsize n_data)
{
	memcpy (data, user_data, n_data);
	return TRUE;
}

static gboolean
anode_encoder_structured (gpointer user_data, guchar *data, gsize n_data)
{
	GNode *node = user_data;
	GNode *child;
	gsize length;
	Atlv *tlv;

	for (child = node->children; child; child = child->next) {
		tlv = anode_get_tlv_data (child);
		if (tlv) {
			length = tlv->off + tlv->len;
			g_assert (length <= n_data);
			if (!anode_encode_build (child, data, length))
				return FALSE;
			data += length;
			n_data -= length;
		}
	}

	return TRUE;
}

static gboolean
anode_encoder_choice (gpointer user_data, guchar *data, gsize n_data)
{
	GNode *node = user_data;
	Aenc *enc = NULL;
	GNode *child;
	Atlv *tlv, *ctlv;

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, FALSE);

	for (child = node->children; child; child = child->next) {
		ctlv = anode_get_tlv_data (child);
		if (ctlv) {
			enc = anode_get_enc_data (child);
			g_return_val_if_fail (enc, FALSE);
			if (!(enc->encoder) (enc->user_data, data, n_data))
				return FALSE;

			/* Child's buffer matches ours */
			ctlv->buf = tlv->buf;
			ctlv->end = tlv->end;
			break;
		}
	}

	return TRUE;
}

static gboolean
anode_encode_prepare_simple (GNode *node)
{
	Aenc *enc;
	Atlv *tlv;

	enc = anode_get_enc_data (node);
	tlv = anode_get_tlv_data (node);
	if (enc != NULL || tlv == NULL)
		return FALSE;

	/* Transfer the tlv data over to enc */
	anode_set_enc_data (node, anode_encoder_simple,
	                    (guchar*)tlv->buf + tlv->off, NULL);
	tlv->buf = tlv->end = NULL;
	return TRUE;
}

static gboolean
anode_encode_prepare_structured (GNode *node)
{
	gsize length = 0;
	gboolean had;
	Atlv *tlv;
	GNode *child;
	gint type;

	type = anode_def_type (node);

	had = FALSE;
	length = 0;

	for (child = node->children; child; child = child->next) {
		if (anode_encode_prepare (child)) {
			tlv = anode_get_tlv_data (child);
			had = TRUE;
			g_return_val_if_fail (tlv, had);
			length += tlv->off + tlv->len;
			if (type == TYPE_CHOICE)
				break;
		}
	}

	if (!had)
		return FALSE;

	/* Choice type, take over the child's encoding */
	if (type == TYPE_CHOICE) {
		if (child) {
			tlv = anode_get_tlv_data (child);
			g_return_val_if_fail (tlv, had);
			anode_clr_tlv_data (node);
			anode_set_tlv_data (node, tlv);
			anode_set_enc_data (node, anode_encoder_choice, node, NULL);
		}

	/* Other container types */
	} else {
		anode_encode_tlv_and_enc (node, length, anode_encoder_structured, node, NULL);
	}

	return TRUE;
}

static gboolean
anode_encode_prepare (GNode *node)
{
	switch (anode_def_type (node)) {
	case TYPE_INTEGER:
	case TYPE_BOOLEAN:
	case TYPE_BIT_STRING:
	case TYPE_OCTET_STRING:
	case TYPE_OBJECT_ID:
	case TYPE_TIME:
	case TYPE_ENUMERATED:
	case TYPE_GENERALSTRING:
	case TYPE_ANY:
		return anode_encode_prepare_simple (node);
		break;
	case TYPE_SEQUENCE:
	case TYPE_SEQUENCE_OF:
	case TYPE_SET:
	case TYPE_SET_OF:
	case TYPE_CHOICE:
		return anode_encode_prepare_structured (node);
		break;
	default:
		g_return_val_if_reached (FALSE);
	};
}

gpointer
egg_asn1x_encode (GNode *asn, EggAllocator allocator, gsize *n_data)
{
	guchar *data;
	gsize length;
	Atlv *tlv;

	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (n_data, NULL);
	g_return_val_if_fail (anode_def_type_is_real (asn), NULL);

	if (!allocator)
		allocator = g_realloc;

	anode_encode_prepare (asn);

	/* We must sort all the nasty SET OF nodes */
	g_node_traverse (asn, G_POST_ORDER, G_TRAVERSE_ALL, -1,
	                 traverse_and_sort_set_of, allocator);

	tlv = anode_get_tlv_data (asn);
	g_return_val_if_fail (tlv, NULL);

	/* Allocate enough memory for entire thingy */
	length = tlv->off + tlv->len;
	data = (allocator) (NULL, length + 1);
	if (data == NULL)
		return NULL;

	if (anode_encode_build (asn, data, length) &&
	    anode_validate_anything (asn)) {
		anode_encode_commit (asn);
		*n_data = length;
		return data;
	}

	(allocator) (data, 0);
	anode_encode_rollback (asn);
	return NULL;
}

/* -----------------------------------------------------------------------------------
 * READING, WRITING, GETTING, SETTING
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
anode_read_time (GNode *node, Atlv *tlv, glong *value)
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
		return anode_failure (node, "invalid time content");

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when.tm_year >= 2038) {
		*value = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		*value = timegm (&when);
		g_return_val_if_fail (*time >= 0, FALSE);
		*value += offset;
	}

	return TRUE;
}

static gboolean
anode_read_integer_as_ulong (GNode *node, Atlv *tlv, gulong *value)
{
	const guchar *p;
	gsize k;

	if (tlv->len < 1 || tlv->len > sizeof (gulong))
		return FALSE;

	p = tlv->buf + tlv->off;
	*value = 0;
	for (k = 0; k < tlv->len; ++k)
		*value |= p[k] << (8 * ((tlv->len - 1) - k));

	return TRUE;
}

static gboolean
anode_write_integer_ulong (gulong value, guchar *data, gsize *n_data)
{
	guchar buf[8];
	gint bytes;

	buf[0] = (value >> 56) & 0xFF;
	buf[1] = (value >> 48) & 0xFF;
	buf[2] = (value >> 40) & 0xFF;
	buf[3] = (value >> 32) & 0xFF;
	buf[4] = (value >> 24) & 0xFF;
	buf[5] = (value >> 16) & 0xFF;
	buf[6] = (value >> 8) & 0xFF;
	buf[7] = (value >> 0) & 0xFF;

	for (bytes = 7; bytes >= 0; --bytes)
		if (!buf[bytes])
			break;

	bytes = 8 - (bytes + 1);
	if (bytes == 0)
		bytes = 1;

	if (data) {
		g_assert (*n_data >= bytes);
		memcpy (data, buf + (8 - bytes), bytes);
	}
	*n_data = bytes;
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
				return anode_failure (node, "invalid encoding of child");
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

static gboolean
anode_read_boolean (GNode *node, Atlv *tlv, gboolean *value)
{
	g_assert (node);
	g_assert (tlv);
	g_assert (value);

	if (tlv->len != 1)
		return FALSE;
	if (tlv->buf[tlv->off] == 0x00)
		*value = FALSE;
	if (tlv->buf[tlv->off] == 0xFF)
		*value = TRUE;
	else
		return FALSE;
	return TRUE;
}

static gboolean
anode_write_boolean (gboolean value, guchar *data, gsize *n_data)
{
	if (data) {
		g_assert (*n_data >= 1);
		if (value)
			data[0] = 0xFF;
		else
			data[0] = 0x00;
	}
	*n_data = 1;
	return TRUE;
}

static gboolean
anode_read_object_id (GNode *node, Atlv *tlv, gchar **oid)
{
	GString *result = NULL;
	const guchar *p;
	gboolean lead;
	guint val, pval;
	gint k;

	g_assert (tlv);
	if (tlv->len <= 0)
		return FALSE;
	p = tlv->buf + tlv->off;

	if (oid)
		result = g_string_sized_new (32);

	pval = p[0] / 40;
	val = p[0] - pval * 40;

	if (result)
		g_string_append_printf (result, "%u.%u.", pval, val);

	/* TODO: Validate first byte? */
	for (k = 1, lead = 1, val = 0, pval = 0; k < tlv->len; ++k) {
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
				g_string_append_printf (result, "%u.", val);
			pval = val = 0;
			lead = 1;
		}
	}

	if (k < tlv->len) {
		if (result)
			g_string_free (result, TRUE);
		return FALSE;
	}

	if (result)
		*oid = g_string_free (result, FALSE);
	return TRUE;
}

static gboolean
anode_write_oid (const gchar *oid, guchar *data, gsize *n_data)
{
	const gchar *p;
	gint num, num1;
	guchar bit7;
	gboolean had;
	gint i, k, at;

	p = oid;
	at = 0;

	for (i = 0; oid[0]; ++i, oid = p) {
		p = strchr (oid, '.');
		if (p == NULL)
			p = oid + strlen (oid);
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
		if (type == TYPE_SEQUENCE_OF || type == TYPE_SET_OF) {
			index = va_arg (va, gint);
			if (index == 0)
				return node;
			node = g_node_nth_child (node, index);
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

gboolean
egg_asn1x_get_boolean (GNode *node, gboolean *value)
{
	Atlv *tlv;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (anode_def_type (node) == TYPE_BOOLEAN, FALSE);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, FALSE);

	return anode_read_boolean (node, tlv, value);
}

gboolean
egg_asn1x_set_boolean (GNode *node, gboolean value)
{
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (anode_def_type (node) == TYPE_BOOLEAN, FALSE);

	n_data = 1;
	data = g_malloc0 (1);
	if (!anode_write_boolean (value, data, &n_data))
		return FALSE;
	anode_encode_tlv_and_enc (node, n_data, anode_encoder_simple, data, g_free);
	return TRUE;
}

gboolean
egg_asn1x_get_integer_as_ulong (GNode *node, gulong *value)
{
	Atlv *tlv;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (anode_def_type (node) == TYPE_INTEGER, FALSE);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, FALSE);

	return anode_read_integer_as_ulong(node, tlv, value);
}

gboolean
egg_asn1x_set_integer_as_ulong (GNode *node, gulong value)
{
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (anode_def_type (node) == TYPE_BOOLEAN, FALSE);

	n_data = 8;
	data = g_malloc0 (8);
	if (!anode_write_integer_ulong (value, data, &n_data))
		return FALSE;
	anode_encode_tlv_and_enc (node, n_data, anode_encoder_simple, data, g_free);
	return TRUE;
}

gconstpointer
egg_asn1x_get_raw_value (GNode *node, gsize *n_content)
{
	Atlv *tlv;

	g_return_val_if_fail (node, NULL);
	g_return_val_if_fail (n_content, NULL);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, NULL);
	g_return_val_if_fail (!(tlv->cls & ASN1_CLASS_STRUCTURED), NULL);

	*n_content = tlv->len;
	return tlv->buf + tlv->off;
}

gboolean
egg_asn1x_set_raw_value (GNode *node, gsize length, EggAsn1xEncoder encoder,
                         gpointer user_data, GDestroyNotify destroy)
{
	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (encoder, FALSE);

	anode_encode_tlv_and_enc (node, length, encoder, user_data, destroy);
	return TRUE;
}

guchar*
egg_asn1x_get_string_as_raw (GNode *node, EggAllocator allocator, gsize *n_string)
{
	gsize length;
	guchar *string;
	Atlv *tlv;
	gint type;

	g_return_val_if_fail (node, NULL);
	g_return_val_if_fail (n_string, NULL);

	type = anode_def_type (node);
	g_return_val_if_fail (type == TYPE_OCTET_STRING || type == TYPE_GENERALSTRING, NULL);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, NULL);

	if (!anode_read_string (node, tlv, NULL, &length))
		return NULL;

	string = (allocator) (NULL, length + 1);
	if (string == NULL)
		return NULL;

	if (!anode_read_string (node, tlv, string, &length)) {
		(allocator) (string, 0);
		return NULL;
	}

	/* Courtesy null termination, string must however be validated! */
	string[length] = 0;
	*n_string = length;
	return string;
}

gboolean
egg_asn1x_set_string_as_raw (GNode *node, guchar *data, gsize n_data, GDestroyNotify destroy)
{
	gint type;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (data, FALSE);

	type = anode_def_type (node);
	g_return_val_if_fail (type == TYPE_OCTET_STRING || type == TYPE_GENERALSTRING, FALSE);

	anode_encode_tlv_and_enc (node, n_data, anode_encoder_simple, data, destroy);
	return TRUE;
}

gchar*
egg_asn1x_get_string_as_utf8 (GNode *node, EggAllocator allocator)
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
egg_asn1x_set_string_as_utf8 (GNode *node, gchar *data, GDestroyNotify destroy)
{
	gsize n_data;

	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (data, FALSE);

	n_data = strlen (data);
	if (!g_utf8_validate (data, n_data, NULL))
		return FALSE;

	return egg_asn1x_set_string_as_raw (node, (guchar*)data, n_data, destroy);
}

glong
egg_asn1x_get_time_as_long (GNode *node)
{
	Atlv *tlv;
	glong time;

	g_return_val_if_fail (node, -1);
	g_return_val_if_fail (anode_def_type (node) == TYPE_TIME, -1);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, -1);

	if (!anode_read_time (node, tlv, &time))
		return -1;
	return time;
}

gchar*
egg_asn1x_get_oid_as_string (GNode *node)
{
	gchar *oid;
	Atlv *tlv;

	g_return_val_if_fail (node, NULL);
	g_return_val_if_fail (anode_def_type (node) == TYPE_OBJECT_ID, NULL);

	tlv = anode_get_tlv_data (node);
	g_return_val_if_fail (tlv, NULL);

	if (!anode_read_object_id (node, tlv, &oid))
		return NULL;

	return oid;
}

gboolean
egg_asn1x_set_oid_as_string (GNode *node, const gchar *oid)
{
	guchar *data;
	gsize n_data;

	g_return_val_if_fail (oid, FALSE);
	g_return_val_if_fail (node, FALSE);
	g_return_val_if_fail (anode_def_type (node) == TYPE_OBJECT_ID, FALSE);

	/* Encoding will always be shorter than string */
	n_data = strlen (oid);
	data = g_malloc0 (n_data);

	if (!anode_write_oid (oid, data, &n_data)) {
		g_free (data);
		return FALSE;
	}

	anode_encode_tlv_and_enc (node, n_data, anode_encoder_simple, data, g_free);
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
egg_asn1x_set_oid_as_quark (GNode *node, GQuark oid)
{
	const gchar *str;

	g_return_val_if_fail (oid, FALSE);
	str = g_quark_to_string (oid);
	g_return_val_if_fail (str, FALSE);

	return egg_asn1x_set_oid_as_string (node, str);
}

/* -----------------------------------------------------------------------------------
 * VALIDATION
 */

static gboolean
anode_parse_size (GNode *node, const gchar *text, gulong *value)
{
	ASN1_ARRAY_TYPE *def;
	gchar *end = NULL;

	if (text == NULL) {
		*value = 0;
		return FALSE;
	} else if (g_str_equal (text, "MAX")) {
		*value = G_MAXULONG;
		return TRUE;
	} else if (g_ascii_isalpha (text[0])) {
		def = anode_opt_lookup (node, TYPE_INTEGER, text);
		g_return_val_if_fail (def, FALSE);
		return anode_parse_size (node, def->value, value);
	}

	*value = strtoul (text, &end, 10);
	g_return_val_if_fail (end && !end[0], FALSE);
	return TRUE;
}


static gboolean
anode_validate_size (GNode *node, gulong length)
{
	ASN1_ARRAY_TYPE *size;
	gulong value1 = 0;
	gulong value2 = G_MAXULONG;

	if (anode_def_flags (node) & FLAG_SIZE) {
		size = anode_opt_lookup (node, TYPE_SIZE, NULL);
		if (size == NULL) {
			egg_asn1x_dump (g_node_get_root (node));
		}
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
anode_validate_integer (GNode *node, Atlv *tlv)
{
	GList *constants, *l;
	gulong value, check;
	gboolean found;
	gint flags;

	g_assert (tlv);

	/* Integers must be at least one byte long */
	if (tlv->len <= 0)
		return anode_failure (node, "zero length integer");

	flags = anode_def_flags (node);
	if (flags & FLAG_LIST) {
		/* Parse out the value, we only support small integers*/
		if (!anode_read_integer_as_ulong (node, tlv, &value))
			return anode_failure (node, "integer not part of list");

		/* Look through the list of constants */
		found = FALSE;
		constants = anode_opts_lookup (node, TYPE_CONSTANT, NULL);
		for (l = constants; l; l = g_list_next (l)) {
			check = anode_def_value_as_ulong (l->data);
			g_return_val_if_fail (check != G_MAXULONG, FALSE);
			if (check == value) {
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
anode_validate_enumerated (GNode *node, Atlv *tlv)
{
	g_assert (tlv);

	if (!anode_validate_integer (node, tlv))
		return FALSE;
	g_assert (tlv->len); /* Checked above */
	/* Enumerated must be positive */
	if (tlv->buf[tlv->off] & 0x80)
		return anode_failure (node, "enumerated must be positive");
	return TRUE;
}

static gboolean
anode_validate_boolean (GNode *node, Atlv *tlv)
{
	g_assert (tlv);

	/* Must one byte, and zero or all ones */
	if (tlv->len != 1)
		return anode_failure (node, "invalid length boolean");
	if (tlv->buf[tlv->off] != 0x00 && tlv->buf[tlv->off] != 0xFF)
		return anode_failure (node, "boolean must be true or false");
	return TRUE;
}

static gboolean
anode_validate_bit_string (GNode *node, Atlv *tlv)
{
	guchar empty, mask;
	g_assert (tlv);

	/* At least two bytes in length */
	if (tlv->len < 2)
		return anode_failure (node, "invalid length bit string");
	/* First byte is the number of free bits at end */
	empty = tlv->buf[tlv->off];
	if (empty > 7)
		return anode_failure (node, "bit string has invalid header");
	/* Free bits at end must be zero */
	mask = 0xFF >> (8 - empty);
	if (tlv->buf[tlv->off + tlv->len - 1] & mask)
		return anode_failure (node, "bit string has invalid trailing bits");
	return TRUE;
}

static gboolean
anode_validate_string (GNode *node, Atlv *tlv)
{
	gsize length;

	if (!anode_read_string (node, tlv, NULL, &length))
		return anode_failure (node, "string content is invalid");

	return anode_validate_size (node, (gulong)length);
}

static gboolean
anode_validate_object_id (GNode *node, Atlv *tlv)
{
	return anode_read_object_id (node, tlv, NULL);
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
	for (child = node->children; child; child = child->next) {
		if (anode_get_tlv_data (child)) {
			if (have)
				return anode_failure (node, "only one choice may be set");
			have = TRUE;
			if (!anode_validate_anything (child))
				return FALSE;
		}
	}

	if (!have)
		return anode_failure (node, "one choice must be set");
	return TRUE;
}

static gboolean
anode_validate_sequence_or_set (GNode *node)
{
	GNode *child;
	gulong tag;
	gint count = 0;
	gint type;
	Atlv *tlv;

	type = anode_def_type (node);

	/* All of the children must validate properly */
	for (child = node->children; child; child = child->next) {
		if (!anode_validate_anything (child))
			return FALSE;

		/* Tags must be in ascending order */
		tlv = anode_get_tlv_data (child);
		if (tlv && type == TYPE_SET) {
			if (count > 0 && tag > tlv->tag)
				return anode_failure (node, "content must be in ascending order");
			tag = tlv->tag;
			++count;
		}
	}

	return TRUE;
}

static gboolean
anode_validate_sequence_or_set_of (GNode *node)
{
	GNode *child;
	Atlv *tlv, *ptlv;
	gulong tag;
	gulong count;
	gint type;

	count = 0;
	tlv = ptlv = NULL;

	type = anode_def_type (node);

	/* All the children must validate properly */
	for (child = node->children; child; child = child->next) {
		if (!anode_validate_anything (child))
			return FALSE;

		tlv = anode_get_tlv_data (child);
		if (tlv) {
			/* Tag must have same tag as top */
			if (count == 0)
				tag = anode_calc_tag (child);
			else if (tag != G_MAXULONG && tlv->tag != tag)
				return anode_failure (node, "invalid mismatched content");

			/* Set of must be in ascending order */
			if (type == TYPE_SET_OF && ptlv && compare_tlvs (ptlv, tlv) > 0)
				return anode_failure (node, "content must be in ascending order");
			ptlv = tlv;
			++count;
		}
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
		return anode_failure (node, "missing value");
	}

	g_return_val_if_fail (tlv->buf, FALSE);

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

	taga = anode_calc_tag (na);
	g_return_val_if_fail (taga != G_MAXULONG, 0);

	tagb = anode_calc_tag (nb);
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

static const ASN1_ARRAY_TYPE*
lookup_def (const ASN1_ARRAY_TYPE *defs, const gchar *identifier, gint type)
{
	/* Find the one we're interested in */
	while (defs && (defs->value || defs->type || defs->name)) {
		if ((defs->type & 0xFF) == type &&
		    defs->name && g_str_equal (identifier, defs->name))
			return defs;
		++defs;
	}

	return NULL;
}

static gboolean
traverse_and_prepare (GNode *node, gpointer data)
{
	const ASN1_ARRAY_TYPE *defs = data;
	const ASN1_ARRAY_TYPE *def;
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

	if (join)
		g_node_children_foreach (join, G_TRAVERSE_ALL, join_each_child, node);

	/* Lookup the max set size */
	if (anode_def_type (node) == TYPE_SIZE) {
		identifier = anode_def_name (node);
		if (identifier && !g_str_equal (identifier, "MAX") &&
		    g_ascii_isalpha (identifier[0])) {
			def = lookup_def (defs, identifier, TYPE_INTEGER);
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
				g_node_destroy (child);
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
	if (anode_def_type (node) == TYPE_SET) {
		for (child = node->children; child; child = child->next)
			list = g_list_prepend (list, child);
		list = g_list_sort (list, compare_nodes_by_tag);
		for (l = list; l; l = g_list_next (l))
			g_node_unlink (l->data);
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
 * DUMPING and MESSAGES
 */

static void
dump_append_type (GString *output, gint type)
{
	#define XX(x) if (type == TYPE_##x) g_string_append (output, #x " ")
	XX(CONSTANT); XX(IDENTIFIER); XX(INTEGER); XX(BOOLEAN); XX(SEQUENCE); XX(BIT_STRING);
	XX(OCTET_STRING); XX(TAG); XX(DEFAULT); XX(SIZE); XX(SEQUENCE_OF); XX(OBJECT_ID); XX(ANY);
	XX(SET); XX(SET_OF); XX(DEFINITIONS); XX(TIME); XX(CHOICE); XX(IMPORTS); XX(NULL);
	XX(ENUMERATED); XX(GENERALSTRING);
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
	ASN1_ARRAY_TYPE *def;
	guint i, depth;
	GString *output;
	gchar *string;
	Anode *an;
	GList *l;

	depth = g_node_depth (node);
	for (i = 0; i < depth - 1; ++i)
		g_printerr ("    ");

	output = g_string_new ("");
	dump_append_type (output, anode_def_type (node));
	dump_append_flags (output, anode_def_flags (node));
	string = g_utf8_casefold (output->str, output->len - 1);
	g_string_free (output, TRUE);
	g_printerr ("+ %s: %s [%s]\n", anode_def_name (node), anode_def_value (node), string);
	g_free (string);

	/* Print out all the options */
	an = node->data;
	for (l = an->opts; l; l = g_list_next (l)) {
		for (i = 0; i < depth; ++i)
			g_printerr ("    ");

		def = l->data;
		output = g_string_new ("");
		dump_append_type (output, def->type & 0xFF);
		dump_append_flags (output, def->type);
		string = g_utf8_casefold (output->str, output->len - 1);
		g_string_free (output, TRUE);
		g_printerr ("- %s: %s [%s]\n", def->name, (const gchar*)def->value, string);
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
	if (type == TYPE_SET_OF || type == TYPE_SEQUENCE_OF) {

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
	if (data)
		anode_destroy (data);
}
