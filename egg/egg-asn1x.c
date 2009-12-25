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
	struct _Atlv *next;
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
		g_slice_free_chain (Atlv, an->data, next);
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
	case TYPE_SEQUENCE:
	case TYPE_BIT_STRING:
	case TYPE_OCTET_STRING:
	case TYPE_SEQUENCE_OF:
	case TYPE_OBJECT_ID:
	case TYPE_ANY:
	case TYPE_SET:
	case TYPE_SET_OF:
	case TYPE_TIME:
	case TYPE_CHOICE:
	case TYPE_NULL:
	case TYPE_ENUMERATED:
	case TYPE_GENERALSTRING:
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
anode_def_value_as_ulong (GNode *node)
{
	const gchar* value;
	gchar *end = NULL;
	gulong ulval;

	value = anode_def_value (node);
	g_return_val_if_fail (value, G_MAXULONG);
	ulval = strtoul (value, &end, 10);
	g_return_val_if_fail (end && !end[0], G_MAXULONG);
	return ulval;
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

static void
anode_add_tlv_data (GNode *node, Atlv *tlv)
{
	Anode *an = node->data;
	Atlv **last = &an->data;
	g_assert (tlv->len >= 0);
	while (*last)
		last = &(*last)->next;
	*last = g_slice_new0 (Atlv);
	memcpy (*last, tlv, sizeof (tlv));
}

static gulong
anode_encode_tag_for_flags (GNode *node, gint flags)
{
	GNode *child;

	g_return_val_if_fail (anode_def_type_is_real (node), G_MAXULONG);

	/* A context specific tag */
	if (flags & FLAG_TAG) {
		child = anode_child_with_type (node, TYPE_TAG);
		g_return_val_if_fail (child, G_MAXULONG);
		return anode_def_value_as_ulong (child);
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
anode_decode_tlv_ensure_length (Atlv *tlv)
{
	if (tlv->len >= 0)
		return TRUE;

	if (!anode_decode_indefinite_len (tlv->buf + tlv->off, tlv->end, &tlv->len))
		return FALSE;

	g_assert (tlv->len >= 0);
	tlv->end = tlv->buf + tlv->off + tlv->len;
	return TRUE;
}

static gboolean
anode_decode_choice (GNode *node, Atlv *tlv)
{
	GNode *child;

	for (child = anode_child_with_real_type (node);
	     child; child = anode_next_with_real_type (child)) {
		if (anode_decode_anything (child, tlv))
			return TRUE;
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
		anode_add_tlv_data (node, &tlv);
		outer->len = (tlv.end - outer->buf) - outer->off;
	}

	g_assert (outer->len >= 0);
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
		anode_add_tlv_data (node, tlv);
		return TRUE;

	/* Transparent types */
	case TYPE_ANY:
		anode_add_tlv_data (node, tlv);
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
		tlv->len = ctlv.off + ctlv.len;

	/* Other structured types */
	} else {
		switch (anode_def_type (node)) {
		case TYPE_ANY:
			if (!anode_decode_tlv_ensure_length (tlv))
				return FALSE;
			anode_add_tlv_data (node, tlv);
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
		tlv->len += off;
		end = tlv->buf + tlv->off + tlv->len;
	}

	/* A structure must be filled up, no stuff ignored */
	if (tlv->buf + tlv->off + tlv->len != end)
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

	if (tlv.buf + tlv.off + tlv.len != tlv.end)
		return FALSE;

	return TRUE;
}

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
