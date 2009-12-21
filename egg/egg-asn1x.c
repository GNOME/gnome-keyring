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
	CONST_UNIVERSAL = (1<<8),
	CONST_PRIVATE = (1<<9),
	CONST_APPLICATION = (1<<10),
	CONST_EXPLICIT = (1<<11),
	CONST_IMPLICIT = (1<<12),
	CONST_TAG = (1<<13),
	CONST_OPTION = (1<<14),
	CONST_DEFAULT = (1<<15),
	CONST_TRUE = (1<<16),
	CONST_FALSE = (1<<17),
	CONST_LIST = (1<<18),
	CONST_MIN_MAX = (1<<19),
	CONST_1_PARAM = (1<<20),
	CONST_SIZE = (1<<21),
	CONST_DEFINED_BY = (1<<22),
	CONST_GENERALIZED = (1<<23),
	CONST_UTC = (1<<24),
	CONST_IMPORTS = (1<<25),
	CONST_NOT_USED = (1<<26),
	CONST_SET = (1<<27),
	CONST_ASSIGN = (1<<28),
	CONST_DOWN = (1<<29),
	CONST_RIGHT = (1<<30),
};

typedef struct Anode {
	const gchar *name;
	guint type;
	const gchar *value;
	gint state;
	gconstpointer data;
	gsize n_data;
} Anode;

/* Forward Declarations */
static gssize anode_decode_any (GNode*, const guchar*, gsize);

static Anode*
anode_new (const ASN1_ARRAY_TYPE *def)
{
	Anode *an = g_slice_new0 (Anode);
	an->name = def->name;
	an->value = def->value;
	an->type = def->type;
	an->state = NO_VALUE;
	an->data = NULL;
	an->n_data = 0;
	return an;
}

static void
anode_free (gpointer data)
{
	if (data)
		g_slice_free (Anode, data);
}

#if 0
static Anode*
anode_decode_until (GNode **node, int type)
{
	Anode *an;

	g_assert (*node);
	while (*node) {
		an = (*node)->data;
		if ((an->type & 0xFF) == type)
			return an;

		/* The node must be optional or have a default */
		g_assert_not_reached (); /* TODO: */
		*node = (*node)->next;
	}

	return NULL;
}




static GNode*
anode_decode_utc_time (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	if (n_data < 6 || n_data >= 28)
		return NULL;
	an->data = data;
	an->n_data = n_data;
	return node;
}

static GNode*
anode_decode_generalized_time (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	if (n_data < 8 || n_data >= 30)
		return NULL;
	an->data = data;
	an->n_data = n_data;
	return node;
}

static GNode*
anode_decode_sequence (GNode *node, const guchar *data, gsize n_data)
{

}

static gssize
anode_decode_any (GNode *node, const guchar *data, gsize n_data)
{
	guchar cls;
	gulong tag;
	gint cb, len;
	gsize offset = 0;
	gsize ret;

	g_assert (node);

	if (asn1_get_tag_der (data, n_data, &cls, &cb, &tag) != ASN1_SUCCESS)
		return -1;

	offset += cb;
	data += cb;
	n_data -= cb;

	len = asn1_get_length_der (data + cb, n_data - cb, &cb);
	if (len < 0)
		return -1;

	offset += cb;
	data += cb;
	n_data -= cb;

	switch (tag) {
	case ASN1_TAG_BOOLEAN:
		ret = anode_decode_boolean (node, data, n_data);
		break;
	case ASN1_TAG_INTEGER:
		ret = anode_decode_value (node, data, n_data);
		break;
	case ASN1_TAG_SEQUENCE:
		ret = anode_decode_sequence (node, data, n_data);
		break;
	case ASN1_TAG_SET:
		ret = anode_decode_set (node, data, n_data);
		break;
	case ASN1_TAG_OCTET_STRING:
		ret = anode_decode_value (node, data, n_data);
		break;
	case ASN1_TAG_BIT_STRING:
		ret = anode_decode_bit_string (node, data, n_data);
		break;
	case ASN1_TAG_UTCTime:
		ret = anode_decode_utc_time (node, data, n_data);
		break;
	case ASN1_TAG_GENERALIZEDTime:
		ret = anode_decode_generalized_time (node, data, n_data);
		break;
	case ASN1_TAG_OBJECT_ID:
		ret = anode_decode_value (node, data, n_data);
		break;
	case ASN1_TAG_ENUMERATED:
		ret = anode_decode_enumerated (node, data, n_data);
		break;
	case ASN1_TAG_NULL:
		ret = anode_decode_null (node, data, n_data);
		break;
	case ASN1_TAG_GENERALSTRING:
		ret = anode_decode_value (node, data, n_data);
		break;
	default:
		g_return_val_if_reached (-1);
	}

	g_printerr ("class: %u(%x) / len: %d / tag: %lu\n", (guint)cls, (guint)(cls & 0x1F), len, tag);
	return offset + len;
}
#endif

static gsize
anode_decode_tag (int ctag, int ccls, const guchar *data, gsize n_data)
{
	guchar cls;
	gulong tag;
	gint cb, len;
	gsize offset = 0;

	if (asn1_get_tag_der (data, n_data, &cls, &cb, &tag) != ASN1_SUCCESS)
		return 0;
	if (cls != ccls || tag != ctag)
		return 0;

	offset += cb;
	data += cb;
	n_data -= cb;

	len = asn1_get_length_der (data, n_data , &cb);
	if (len < 0)
		return 0;

	offset += cb;
	n_data -= cb;
	if (len != n_data)
		return 0;

	return offset;
}

static gsize
anode_decode_length (const guchar *data, gsize n_data)
{
	guchar cls;
	gulong tag;
	gint cb1, cb2, len;

	if (asn1_get_tag_der (data, n_data, &cls, &cb1, &tag) != ASN1_SUCCESS)
		return -1;
	len = asn1_get_length_der (data + cb1, n_data - cb1, &cb2);
	if (len < 0)
		return -1;
	return len + cb1 + cb2;
}

static gboolean
anode_decode_boolean (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset;

	offset = anode_decode_tag (ASN1_TAG_BOOLEAN, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	data += offset;
	n_data -= offset;
	if (n_data != 1)
		return FALSE;
	if (data[0] != 1 && data[0] != 0)
		return FALSE;
	an->data = data;
	an->n_data = 1;
	return TRUE;
}

static gboolean
anode_decode_integer (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset;

	offset = anode_decode_tag (ASN1_TAG_INTEGER, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	an->data = data + offset;
	an->n_data = n_data - offset;
	return TRUE;
}

static gboolean
anode_decode_bit_string (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset = anode_decode_tag (ASN1_TAG_BIT_STRING, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	data += offset;
	n_data -= offset;
	if (n_data < 2)
		return FALSE;
	if (data[0] < 8)
		return FALSE;
	an->data = data;
	an->n_data = n_data;
	return TRUE;
}

static gboolean
anode_decode_null (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset = anode_decode_tag (ASN1_TAG_BIT_STRING, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	data += offset;
	n_data -= offset;
	if (n_data - offset != 0)
		return FALSE;
	an->data = data + offset;
	an->n_data = 0;
	return TRUE;
}

static gboolean
anode_decode_octet_string (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset = anode_decode_tag (ASN1_TAG_OCTET_STRING, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	an->data = data + offset;
	an->n_data = n_data - offset;
	return TRUE;
}

static gboolean
anode_decode_time (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset = anode_decode_tag (ASN1_TAG_UTCTime, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		offset = anode_decode_tag (ASN1_TAG_GENERALIZEDTime, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	/* TODO: More validation */
	an->data = data + offset;
	an->n_data = n_data - offset;
	return TRUE;
}

static gboolean
anode_decode_generalstring (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gsize offset = anode_decode_tag (ASN1_TAG_GENERALSTRING, ASN1_CLASS_UNIVERSAL, data, n_data);
	if (!offset)
		return FALSE;
	/* TODO: More validation */
	an->data = data + offset;
	an->n_data = n_data - offset;
	return TRUE;
}

static gboolean
anode_decode_sequence (GNode *node, const guchar *data, gsize n_data)
{
	GNode *child;
	gssize length;
	gsize offset;

	offset  = anode_decode_tag (ASN1_TAG_SEQUENCE, ASN1_CLASS_STRUCTURED, data, n_data);
	if (!offset)
		return FALSE;
	data += offset;
	n_data -= offset;

	for (child = node->children; child; child = child->next) {
		length = anode_decode_length (data, n_data);
		if (length < 0)
			return FALSE;
		g_assert (length <= n_data);
		if (!anode_decode_any (child, data, length))
			return FALSE;
		data += length;
		n_data -= length;
	}

	return TRUE;
}

static gssize
anode_decode_any (GNode *node, const guchar *data, gsize n_data)
{
	Anode *an = node->data;
	gboolean ret = FALSE;

	switch (an->type & 0xFF) {
	case TYPE_INTEGER:
		ret = anode_decode_integer (node, data, n_data);
		break;
	case TYPE_BOOLEAN:
		ret = anode_decode_boolean (node, data, n_data);
		break;
	case TYPE_BIT_STRING:
		ret = anode_decode_bit_string (node, data, n_data);
		break;
	case TYPE_OCTET_STRING:
		ret = anode_decode_octet_string (node, data, n_data);
		break;
	case TYPE_TIME:
		ret = anode_decode_time (node, data, n_data);
		break;
	case TYPE_NULL:
		ret = anode_decode_null (node, data, n_data);
		break;
	case TYPE_GENERALSTRING:
		ret = anode_decode_generalstring (node, data, n_data);
		break;
	case TYPE_SEQUENCE:
		ret = anode_decode_sequence (node, data, n_data);
		break;

	case TYPE_CONSTANT:
	case TYPE_IDENTIFIER:
	case TYPE_SEQUENCE_OF:
	case TYPE_TAG:
	case TYPE_DEFAULT:
	case TYPE_SIZE:
	case TYPE_OBJECT_ID:
	case TYPE_ANY:
	case TYPE_SET:
	case TYPE_SET_OF:
	case TYPE_DEFINITIONS:
	case TYPE_CHOICE:
	case TYPE_IMPORTS:
	case TYPE_ENUMERATED:
		g_assert_not_reached (); /* TODO: */
		break;
	}

	if (!ret) {
		/* Try to parse a context specific tag thingy */

		g_assert_not_reached (); /* TODO: Implement checking */
	}

	return ret;
}

gboolean
egg_asn1x_decode (GNode *asn, gconstpointer data, gsize n_data)
{
	g_return_val_if_fail (asn, FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	return anode_decode_any (asn, data, n_data);
}

static void
move_each_child (GNode *child, gpointer data)
{
	GNode *node = data;
	g_node_unlink (child);
	g_node_append (node, child);
}

static gboolean
traverse_and_create_identifier (GNode *node, gpointer data)
{
	const ASN1_ARRAY_TYPE *defs = data;
	Anode *an = node->data;
	Anode *ans;
	GNode *seq;

	if ((an->type & 0xFF) == TYPE_IDENTIFIER) {
		seq = egg_asn1x_create (defs, an->value);
		g_return_val_if_fail (seq, TRUE);
		ans = seq->data;
		an->type = ans->type;
		g_node_children_foreach (seq, G_TRAVERSE_ALL, move_each_child, node);
	}

	return FALSE;
}

GNode*
egg_asn1x_create (const ASN1_ARRAY_TYPE *defs, const gchar *identifier)
{
	const ASN1_ARRAY_TYPE *def;
	GNode *root, *parent, *node;
	Anode *an;

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
	an = anode_new (def);
	root = g_node_new (an);

	/* Build up nodes for underlying level */
	if (def->type & CONST_DOWN) {
		node = root;
		for (;;) {
			if (def->type & CONST_DOWN) {
				parent = node;
			} else if (def->type & CONST_RIGHT) {
				g_assert (node->parent);
				parent = node->parent;
			} else {
				parent = node->parent;
				while (parent) {
					an = parent->data;
					parent = parent->parent;
					if (an->type & CONST_RIGHT)
						break;
				}
			}

			if (!parent)
				break;

			++def;
			node = g_node_new (anode_new (def));
			g_node_append (parent, node);
		}
	}

	/* Load up sub identifiers */
	g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
	                 traverse_and_create_identifier, (gpointer)defs);

	return root;
}

static gboolean
traverse_and_dump (GNode *node, gpointer data)
{
	guint i, depth;
	Anode *an;
	depth = g_node_depth (node);
	for (i = 0; i < depth - 1; ++i)
		g_printerr ("    ");
	an = node->data;
	g_printerr ("%s: %s [%08x]\n", an->name, an->value, (guint)an->type);
	return FALSE;
}

void
egg_asn1x_dump (GNode *asn)
{
	guint depth = 0;
	g_return_if_fail (asn);
	g_node_traverse (asn, G_PRE_ORDER, G_TRAVERSE_ALL, -1, traverse_and_dump, &depth);
}

static gboolean
traverse_and_free (GNode *node, gpointer data)
{
	anode_free (node->data);
	return FALSE;
}

void
egg_asn1x_destroy (gpointer data)
{
	GNode *asn = data;
	if (!data)
		return;
	g_node_traverse (asn, G_IN_ORDER, G_TRAVERSE_ALL, -1, traverse_and_free, NULL);
	g_node_destroy (asn);
}
