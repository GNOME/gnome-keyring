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

typedef struct _Adata {
	gconstpointer buf;
	gsize n_buf;
	struct _Adata *next;
} Adata;

typedef struct _Anode {
	const ASN1_ARRAY_TYPE *def;
	const ASN1_ARRAY_TYPE *join;
	Adata *data;
} Anode;

/* TODO: Validate: LIST SIZE */

/* Forward Declarations */
static gssize anode_decode_anything (GNode*, const guchar*, gsize);

static GNode*
anode_new (const ASN1_ARRAY_TYPE *def)
{
	Anode *an = g_slice_new0 (Anode);
	an->def = def;
	an->data = NULL;
	return g_node_new (an);
}

static gboolean
anode_free_func (GNode *node, gpointer unused)
{
	Anode *an = node->data;
	if (an->data);
		g_slice_free_chain (Adata, an->data, next);
	g_slice_free (Anode, an);
	return FALSE;
}

static void
anode_destroy (GNode *node)
{
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
anode_child_with_any_data_type (GNode *node)
{
	GNode *child;

	for (child = node->children; child; child = child->next) {
		switch (anode_def_type (child)) {
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
			return child;
		case TYPE_CONSTANT:
		case TYPE_IDENTIFIER:
		case TYPE_TAG:
		case TYPE_DEFAULT:
		case TYPE_SIZE:
		case TYPE_DEFINITIONS:
		case TYPE_IMPORTS:
			break;
		default:
			g_return_val_if_reached (NULL);
		}
	}

	return NULL;
}

static gssize
anode_decode_cls_tag_len (const guchar *data, gsize n_data,
                          guchar *cls, gulong *tag, gint *len)
{
	gint cb1, cb2;
	if (asn1_get_tag_der (data, n_data, cls, &cb1, tag) != ASN1_SUCCESS)
		return -1;
	*len = asn1_get_length_der (data + cb1, n_data - cb1, &cb2);
	if (*len < -1)
		return -1;
	if (*len == -1)
		*len = G_MAXINT;
	else if (cb1 + cb2 + *len > n_data)
		return -1;
	return cb1 + cb2;
}

static gssize
anode_decode_indefinite_len (const guchar *data, gsize n_data)
{
	gssize result = 0;
	gint len;
	guchar cls;
	gulong tag;
	gssize off;

	while (result < n_data) {
		off = anode_decode_cls_tag_len (data + result, n_data - result, &cls, &tag, &len);
		if (off < 0)
			return -1;
		result += off;

		/* The indefinite end */
		if (tag == 0x00 && cls == ASN1_CLASS_UNIVERSAL && len == 0)
			break;

		/* Mid way check */
		if (result > n_data)
			break;

		if (len == G_MAXINT) {
			len = anode_decode_indefinite_len (data + result, n_data - result);
			if (len < 0)
				return -1;
		}

		if (result + len > n_data)
			return -1;
		result += len;
	}

	if (result > n_data)
		return -1;
	return result;
}

static gssize
anode_decode_indefinite_end (const guchar *data, gsize n_data)
{
	gint len;
	guchar cls;
	gulong tag;
	gssize off;

	off = anode_decode_cls_tag_len (data, n_data, &cls, &tag, &len);
	if (off < -1)
		return -1;
	if (tag != 0x00 || cls != ASN1_CLASS_UNIVERSAL || len != 0)
		return 0;
	return off;
}

static gssize
anode_decode_value_data (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	Adata *ad;

	g_return_val_if_fail (!an->data, -1);

	/* All validation is done later */
	ad = g_slice_new0 (Adata);
	ad->buf = data;
	ad->n_buf = n_data;
	an->data = ad;

	return n_data;
}

static gsize
anode_decode_value_chain (GNode *node, gulong of_tag, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	Adata *ad, **last;
	guchar cls;
	gulong tag;
	gssize off, read = 0;
	gint len;

	g_return_val_if_fail (!an->data, -1);

	last = &an->data;
	for (;;) {
		off = anode_decode_cls_tag_len (data + read, n_data - read, &cls, &tag, &len);
		if (off < 0)
			return -1;
		if (len == G_MAXINT)
			return -1;
		read += off;
		if (read > n_data)
			return -1;
		if (len == 0)
			break;

		if (tag != of_tag)
			return -1;

		/* A new data block */
		ad = g_slice_new0 (Adata);
		ad->buf = data + read;
		ad->n_buf = len;

		/* And add it */
		*last = ad;
		last = &ad->next;

		read += len;
		if (read > n_data)
			return -1;
	}

	return read;
}

static gssize
anode_decode_sequence (GNode *node, gboolean definite, const guchar *data, gsize n_data)
{
	GNode *child;
	gssize read, off;

	read = 0;
	for (child = node->children; child; child = child->next) {
		g_assert (read <= n_data);
		off = anode_decode_anything (child, data + read, n_data - read);
		if (off < 0)
			return -1;
		g_assert (off <= n_data - read);
		read += off;
	}

	if (!definite) {
		off = anode_decode_indefinite_end (data + read, n_data - read);
		if (off <= 0)
			return -1;
		read += off;
	}

	return read;
}

static gssize
anode_decode_sequence_or_set_of (GNode *node, gboolean definite, const guchar *data, gsize n_data)
{
	GNode *child, *copy;
	gssize read, off;

	/* The one and only child */
	child = anode_child_with_any_data_type (node);
	g_return_val_if_fail (child, -1);

	/* Try to dig out as many of them as possible */
	read = 0;
	for (;;) {

		/* Definite length, fill up data we were passed */
		if (definite) {
			g_assert (read <= n_data);
			if (read == n_data)
				break;

		/* Indefinite length, look for marker */
		} else {
			off = anode_decode_indefinite_end (data + read, n_data - read);
			if (off < 0)
				return -1;
			read += off;
			if (off != 0)
				break;
		}

		copy = anode_clone (child);
		off = anode_decode_anything (copy, data + read, n_data - read);
		if (off < 0) {
			anode_destroy (copy);
			return -1;
		}
		g_return_val_if_fail (off != 0, -1);
		g_assert (off <= n_data - read);
		read += off;
		g_node_append (node, copy);
	}

	return read;
}

static gssize
anode_decode_choice (GNode *node, const guchar *data, gsize n_data)
{
	GNode *child;
	gssize off;

	for (child = node->children; child; child = child->next) {
		off = anode_decode_anything (child, data, n_data);
		if (off >= 0) {
			g_return_val_if_fail (off == n_data, -1);
			return off;
		}
	}

	return -1;
}

static gssize
anode_decode_value_of_len (GNode *node, guchar cls, gulong tag,
                           const guchar *data, gsize n_data)
{
	gint type, flags, want;

	type = anode_def_type (node);
	switch (type) {

	/* The primitive value types */
	case TYPE_INTEGER:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_INTEGER ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_ENUMERATED:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_ENUMERATED ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_BOOLEAN:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_BOOLEAN ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_BIT_STRING:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_BIT_STRING ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_OCTET_STRING:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_OCTET_STRING ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_OBJECT_ID:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_OBJECT_ID ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_NULL:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_NULL ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;
	case TYPE_GENERALSTRING:
		if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_GENERALSTRING ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
	case TYPE_TIME:
		flags = anode_def_flags (node);
		if (flags & FLAG_GENERALIZED)
			want = ASN1_TAG_GENERALIZEDTime;
		else if (flags & FLAG_UTC)
			want = ASN1_TAG_UTCTime;
		else
			g_return_val_if_reached (-1);
		if (cls != ASN1_CLASS_UNIVERSAL || tag != want ||
		    anode_decode_value_data (node, data, n_data) < 0)
			return -1;
		break;

	/* SEQUENCE: A sequence of child TLV's */
	case TYPE_SEQUENCE:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SEQUENCE ||
		    anode_decode_sequence (node, TRUE, data, n_data) != n_data)
			return -1;
		break;

	/* SEQUENCE OF: A sequence of one type of child TLV */
	case TYPE_SEQUENCE_OF:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SEQUENCE ||
		    anode_decode_sequence_or_set_of (node, TRUE, data, n_data) != n_data)
			return -1;
		break;

	/* SET OF: A set of one type of child TLV */
	case TYPE_SET_OF:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SET ||
		    anode_decode_sequence_or_set_of (node, TRUE, data, n_data) != n_data)
			return -1;
		break;

	case TYPE_SET:
		g_assert (0 && "TODO");
		break;

	/* These should have been handled by caller */
	default:
		g_return_val_if_reached (-1);
	}

	return n_data;
}

static gssize
anode_decode_value_of_indefinite (GNode *node, guchar cls, gulong tag,
                                  const guchar *data, gsize n_data)
{
	gint type;
	gint len;

	type = anode_def_type (node);
	switch (type) {

	/* Not supported with indefinite length */
	case TYPE_INTEGER:
	case TYPE_BOOLEAN:
	case TYPE_BIT_STRING:
	case TYPE_OBJECT_ID:
	case TYPE_NULL:
	case TYPE_TIME:
	case TYPE_ENUMERATED:
		return -1;

	case TYPE_OCTET_STRING:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_OCTET_STRING)
			return -1;
		len = anode_decode_value_chain (node, ASN1_TAG_OCTET_STRING, data, n_data);
		break;
	case TYPE_GENERALSTRING:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_GENERALSTRING)
			return -1;
		len = anode_decode_value_chain (node, ASN1_TAG_GENERALSTRING, data, n_data);
		break;

	/* SEQUENCE: A sequence of child TLV's */
	case TYPE_SEQUENCE:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SEQUENCE)
			return -1;
		len = anode_decode_sequence (node, FALSE, data, n_data);
		break;

	/* SEQUENCE OF: A sequence of one type of child TLV */
	case TYPE_SEQUENCE_OF:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SEQUENCE)
			return -1;
		len = anode_decode_sequence_or_set_of (node, FALSE, data, n_data);
		break;

	/* SET OF: A set of one type of child TLV */
	case TYPE_SET_OF:
		if (cls != (ASN1_CLASS_STRUCTURED | ASN1_CLASS_UNIVERSAL) ||
		    tag != ASN1_TAG_SET)
			return -1;
		len = anode_decode_sequence_or_set_of (node, FALSE, data, n_data);
		break;

	case TYPE_SET:
		g_assert (0 && "TODO");
		break;

	default:
		g_return_val_if_reached (-1);
	}

	return len;
}

static gssize
anode_decode_type_and_value (GNode *node, const guchar *data, gsize n_data)
{
	guchar cls;
	gulong tag;
	gint len;
	gssize off;
	gint type;

	type = anode_def_type (node);

	/* Certain transparent types */
	switch (type) {

	/* CHOICE: The entire TLV is one of children */
	case TYPE_CHOICE:
		return anode_decode_choice (node, data, n_data);

	/* These node types should not appear here */
	case TYPE_CONSTANT:
	case TYPE_IDENTIFIER:
	case TYPE_TAG:
	case TYPE_DEFAULT:
	case TYPE_SIZE:
	case TYPE_DEFINITIONS:
	case TYPE_IMPORTS:
		g_return_val_if_reached (-1);
	}

	/* If we didn't parse the tag above */
	off = anode_decode_cls_tag_len (data, n_data, &cls, &tag, &len);
	if (off < 0)
		return -1;

	/* Concrete types */

	/* The length is indefinite */
	if (len == G_MAXINT) {

		/* ANY: The entire TLV is the value */
		if (type == TYPE_ANY) {
			len = anode_decode_indefinite_len (data + off, n_data - off);
			if (len < 0)
				return -1;
			return anode_decode_value_data (node, data, off + len);

		/* All other concrete types */
		} else {
			len = anode_decode_value_of_indefinite (node, cls, tag, data + off, n_data - off);
		}

	/* The length is definite */
	} else {
		if (off + len > n_data)
			return -1;

		/* ANY: The entire TLV is the value */
		if (type == TYPE_ANY) {
			return anode_decode_value_data (node, data, off + len);

		} else {
			if (anode_decode_value_of_len (node, cls, tag, data + off, len) != len)
				return -1;
		}
	}

	return off + len;
}

static gssize
anode_decode_explicit_or_type (GNode *node, const guchar *data, gsize n_data)
{
	GNode *child;
	guchar cls;
	gulong tag;
	gint len;
	gsize off;
	gint flags;

	flags = anode_def_flags (node);

	/* An explicitly tagged value, is one that has a tag specially assigned. */
	if (flags & FLAG_TAG) {
		off = anode_decode_cls_tag_len (data, n_data, &cls, &tag, &len);
		if (off < 0)
			return -1;
		if (cls != (ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_CLASS_STRUCTURED))
			return -1;
		child = anode_child_with_type (node, TYPE_TAG);
		g_return_val_if_fail (child, -1);
		if (tag != anode_def_value_as_ulong (child))
			return -1;

		/* Definite length */
		if (len != G_MAXINT) {
			if (anode_decode_type_and_value (node, data + off, len) != len)
				return -1;

		/* Indefinite length */
		} else {
			len = anode_decode_type_and_value (node, data + off, n_data - off);
			if (len <= 0 || off + len > n_data)
				return -1;
			off += len;
			len = anode_decode_indefinite_end (data + off, n_data - off);
			if (len <= 0 || off + len > n_data)
				return -1;
		}
		return off + len;
	}

	return anode_decode_type_and_value (node, data, n_data);
}

static gssize
anode_decode_anything (GNode *node, const guchar *data, gsize n_data)
{
	gssize off;
	int flags;

	off = anode_decode_explicit_or_type (node, data, n_data);
	if (off < 0) {
		flags = anode_def_flags (node);
		if (flags & FLAG_OPTION)
			off = 0;
		else if (flags & FLAG_DEFAULT)
			g_assert (0 && "TODO");
	}
	return off;
}

gboolean
egg_asn1x_decode (GNode *asn, gconstpointer data, gsize n_data)
{
	gsize offset;

	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	offset = anode_decode_anything (asn, data, n_data);
	return (offset == n_data);
}

static void
join_each_child (GNode *child, gpointer data)
{
	GNode *node = data;
	g_node_unlink (child);
	g_node_append (node, child);
}

static gboolean
traverse_and_create_joins (GNode *node, gpointer data)
{
	const ASN1_ARRAY_TYPE *defs = data;
	Anode *an, *anj;
	GNode *join = NULL;
	const gchar *identifier;

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
	g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
	                 traverse_and_create_joins, (gpointer)defs);

	return root;
}

static gboolean
traverse_and_dump (GNode *node, gpointer data)
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
	guint depth = 0;
	g_return_if_fail (asn);
	g_node_traverse (asn, G_PRE_ORDER, G_TRAVERSE_ALL, -1, traverse_and_dump, &depth);
}

void
egg_asn1x_destroy (gpointer data)
{
	if (data)
		anode_destroy (data);
}
