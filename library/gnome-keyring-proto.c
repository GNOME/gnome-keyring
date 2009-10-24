/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-proto.c - helper code for the keyring daemon protocol

   Copyright (C) 2003 Red Hat, Inc

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

   Author: Alexander Larsson <alexl@redhat.com>
*/
#include "config.h"

#include <string.h>
#include <stdarg.h>

#include "gnome-keyring-proto.h"
#include "gnome-keyring-private.h"

#include "egg/egg-buffer.h"
#include "egg/egg-secure-memory.h"

void 
gkr_proto_go_secure (EggBuffer *buffer)
{
	egg_buffer_set_allocator (buffer, egg_secure_realloc);
}

void
gkr_proto_add_time (EggBuffer *buffer, time_t time)
{
	guint64 val;

	val = time;
	egg_buffer_add_uint32 (buffer, ((val >> 32) & 0xffffffff));
	egg_buffer_add_uint32 (buffer, (val & 0xffffffff));
}

gboolean
gkr_proto_get_time (EggBuffer *buffer, gsize offset, gsize *next_offset,
                    time_t *time)
{
	guint32 a, b;
	guint64 val;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &a)) {
		return FALSE;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &b)) {
		return FALSE;
	}

	val = ((guint64)a) << 32 | b;
	
	*next_offset = offset;
	*time = (time_t) val;
	
	return TRUE;
}

gboolean
gkr_proto_add_utf8_secret (EggBuffer *buffer, const char *str)
{
	/* Make sure this buffer is using non-pageable memory */	
	gkr_proto_go_secure (buffer);
	
	return gkr_proto_add_utf8_string (buffer, str);
}

gboolean
gkr_proto_add_utf8_string (EggBuffer *buffer, const char *str)
{
	gsize len;

	if (str != NULL) {
		len = strlen (str);
	
		if (!g_utf8_validate (str, len, NULL)) {
			return FALSE;
		}
	} else {
		len = 0;
	} 

	return 	egg_buffer_add_string (buffer, str);
}

gboolean
gkr_proto_get_bytes (EggBuffer *buffer, gsize offset, gsize *next_offset,
                     guchar *out, gsize n_bytes)
{
	if (buffer->len < n_bytes ||
	    offset > buffer->len - n_bytes) {
		return FALSE;
	}

	memcpy (out, buffer->buf + offset, n_bytes);
	*next_offset = offset + n_bytes;
	
	return TRUE;
}

gboolean
gkr_proto_get_raw_secret (EggBuffer *buffer, gsize offset, gsize *next_offset,
                          guchar **secret, gsize *n_secret)
{
	const guchar* ptr;
	if (!egg_buffer_get_byte_array (buffer, offset, next_offset, &ptr, n_secret))
		return FALSE;

	if (ptr == NULL || *n_secret == 0) {
		*secret = NULL;
		*n_secret = 0;
		return TRUE;
	}

	*secret = egg_secure_alloc (*n_secret + 1);
	memcpy (*secret, ptr, *n_secret);
	(*secret)[*n_secret] = 0;
	return TRUE;
}

gboolean
gkr_proto_get_utf8_string (EggBuffer *buffer, gsize offset, gsize *next_offset,
                           char **str_ret)
{
	return gkr_proto_get_utf8_full (buffer, offset, next_offset, 
	                                str_ret, (EggBufferAllocator)g_realloc);
}

gboolean
gkr_proto_get_utf8_secret (EggBuffer *buffer, gsize offset, gsize *next_offset,
                           char **str_ret)
{
	return gkr_proto_get_utf8_full (buffer, offset, next_offset, 
	                                str_ret, egg_secure_realloc);
}

gboolean
gkr_proto_get_utf8_full (EggBuffer *buffer, gsize offset, gsize *next_offset,
                         char **str_ret, EggBufferAllocator allocator)
{
	gsize len;
	char *str;
	
	if (!egg_buffer_get_string (buffer, offset, &offset, &str, allocator))
		return FALSE;
	len = str ? strlen (str) : 0;

	if (str != NULL) {
		if (!g_utf8_validate (str, len, NULL)) {
			(allocator) (str, 0); /* frees memory */
			return FALSE;
		}
	}

	if (next_offset != NULL) {
		*next_offset = offset;
	}
	if (str_ret != NULL) {
		*str_ret = str;
	} else {
		(allocator) (str, 0); /* frees memory */
	}
	return TRUE;
}

static gboolean
gkr_proto_start_operation (EggBuffer *buffer, GnomeKeyringOpCode op,
                           gsize *op_start)
{
	gsize appname_pos;
	const char *name;

	appname_pos = buffer->len;
	egg_buffer_add_uint32 (buffer, 0);
	
	name = g_get_application_name ();
	if (name != NULL && !g_utf8_validate (name, -1, NULL)) {
		g_warning ("g_application_name not utf8 encoded");
		name = NULL;
	} else if (name == NULL) {
		g_warning ("g_set_application_name not set.");
	}
	if (name == NULL) {
		/* General name if none set */
		name = "Application";
	}
	if (!gkr_proto_add_utf8_string (buffer, name)) {
		return FALSE;
	}

	/* backpatch application name size */
	if (!egg_buffer_set_uint32 (buffer, appname_pos, buffer->len)) {
		return FALSE;
	}

	
	/* Make space for packet size */
	*op_start = buffer->len;
	egg_buffer_add_uint32 (buffer, 0);
	egg_buffer_add_uint32 (buffer, op);
	
	return TRUE;
}

static gboolean
gkr_proto_end_operation (EggBuffer *buffer, gsize op_start)
{
	if (!egg_buffer_set_uint32 (buffer, op_start, buffer->len - op_start)) {
		return FALSE;
	}
	return TRUE;
}

gboolean
gkr_proto_decode_packet_size (EggBuffer *buffer, guint32 *size)
{
	return egg_buffer_get_uint32 (buffer, 0, NULL, size);
}

gboolean
gkr_proto_decode_packet_operation (EggBuffer *buffer, GnomeKeyringOpCode *op)
{
	guint32 op_nr;
	gboolean res;

	res = egg_buffer_get_uint32 (buffer, 4, NULL, &op_nr);
	*op = op_nr;
	return res;
}

gboolean
gkr_proto_encode_op_only (EggBuffer *buffer, GnomeKeyringOpCode op)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, op, &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_end_operation (buffer,	op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_op_string (EggBuffer *buffer, GnomeKeyringOpCode op,
                            const char *str)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, op, &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, str)) {
		return FALSE;
	}
	if (!gkr_proto_end_operation (buffer,	op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_op_string_int (EggBuffer *buffer, GnomeKeyringOpCode op,
                                const char *str, guint32 val)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, op, &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, str)) {
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer,	val);
	if (!gkr_proto_end_operation (buffer,	op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_op_string_int_int (EggBuffer *buffer, GnomeKeyringOpCode op,
                                    const char *str, guint32 integer1,
                                    guint32 integer2)
{
	gsize op_start;
	if (!gkr_proto_start_operation (buffer, op, &op_start))
		return FALSE;
	if (!gkr_proto_add_utf8_string (buffer, str))
		return FALSE;
	egg_buffer_add_uint32 (buffer,	integer1);
	egg_buffer_add_uint32 (buffer,	integer2);
	if (!gkr_proto_end_operation (buffer, op_start))
		return FALSE;
	return TRUE;
}

gboolean
gkr_proto_encode_op_string_secret (EggBuffer *buffer, GnomeKeyringOpCode op,
                                   const char *str1, const char *str2)
{
	gsize op_start;
	
	/* Make sure we're using non-pageable memory */
	gkr_proto_go_secure (buffer);

	if (!gkr_proto_start_operation (buffer, op, &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, str1)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_secret (buffer, str2)) {
		return FALSE;
	}
	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_op_string_secret_secret (EggBuffer *buffer, GnomeKeyringOpCode op,
                                          const char *str1, const char *str2,
                                          const char *str3)
{
	gsize op_start;

	/* Make sure we're using non-pageable memory */
	gkr_proto_go_secure (buffer);

	if (!gkr_proto_start_operation (buffer, op, &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, str1)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_secret (buffer, str2)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_secret (buffer, str3)) {
		return FALSE;
	}
	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_find (EggBuffer *buffer, GnomeKeyringItemType type,
                       GnomeKeyringAttributeList *attributes)
{
	gsize op_start;
	
	gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_FIND, &op_start);

	egg_buffer_add_uint32 (buffer, type);

	if (!gkr_proto_add_attribute_list (buffer, attributes)) {
		goto bail;
	}
	
	if (!gkr_proto_end_operation (buffer, op_start)) {
		goto bail;
	}

	return TRUE;
	
 bail:
 	egg_buffer_resize (buffer, op_start);
	return FALSE;
}

gboolean
gkr_proto_encode_create_item (EggBuffer *buffer, const char *keyring, 
                              const char *display_name, 
                              GnomeKeyringAttributeList *attributes,
                              const char *secret, GnomeKeyringItemType type,
                              gboolean update_if_exists)
{
	gsize op_start;

	/* Make sure this buffer is using non-pageable memory */	
	gkr_proto_go_secure (buffer);

	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_CREATE_ITEM,
	                                &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, keyring)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, display_name)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_secret (buffer, secret)) {
		return FALSE;
	}
	if (!gkr_proto_add_attribute_list (buffer, attributes)) {
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer, type);
	egg_buffer_add_uint32 (buffer, update_if_exists);
	
	if (!gkr_proto_end_operation (buffer,	op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_decode_create_item (EggBuffer *buffer, char **keyring, char **display_name,
                              GnomeKeyringAttributeList **attributes, char **secret,
                              GnomeKeyringItemType *type, gboolean *update_if_exists)
{
	gsize offset;
	GnomeKeyringOpCode op;
	guint val;

	if (keyring != NULL) {
		*keyring  = NULL;
	}
	if (display_name != NULL) {
		*display_name  = NULL;
	}
	if (secret != NULL) {
		*secret  = NULL;
	}
	if (attributes != NULL) {
		*attributes = NULL;
	}
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_CREATE_ITEM) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, display_name)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, secret)) {
		goto bail;
	}
	
	if (!gkr_proto_decode_attribute_list (buffer, offset, &offset, attributes)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &val)) {
		goto bail;
	}
	if (type != NULL) {
		*type = val;
	}

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &val)) {
		goto bail;
	}
	if (update_if_exists != NULL) {
		*update_if_exists = val;
	}

	return TRUE;
	
 bail:
	if (attributes != NULL) {
		gnome_keyring_attribute_list_free (*attributes);
	}
	if (keyring != NULL) {
		g_free (*keyring);
	}
	if (display_name != NULL) {
		g_free (*display_name);
	}
	if (secret != NULL) {
		egg_secure_strfree (*secret);
	}
	return FALSE;
	
}


gboolean
gkr_proto_encode_set_attributes (EggBuffer *buffer, const char *keyring,
                                 guint32 id, GnomeKeyringAttributeList *attributes)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_SET_ITEM_ATTRIBUTES,
	                                &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, keyring)) {
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer, id);
	
	if (!gkr_proto_add_attribute_list (buffer, attributes)) {
		return FALSE;
	}
	
	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_set_acl (EggBuffer *buffer, const char *keyring,
                          guint32 id, GList *acl)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_SET_ITEM_ACL,
	                                &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, keyring)) {
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer, id);
	
	if (!gkr_proto_add_acl (buffer, acl)) {
		return FALSE;
	}
	
	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}


gboolean
gkr_proto_encode_set_item_info (EggBuffer *buffer, const char *keyring,
                                guint32 id, GnomeKeyringItemInfo *info)
{
	gsize op_start;
	
	/* Make sure this buffer is using non-pageable memory */	
	gkr_proto_go_secure (buffer);

	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_SET_ITEM_INFO,
	                                &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, keyring)) {
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer, id);
	
	egg_buffer_add_uint32 (buffer, info->type);
	if (!gkr_proto_add_utf8_string (buffer, info->display_name)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_secret (buffer, info->secret)) {
		return FALSE;
	}
	
	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_set_keyring_info (EggBuffer *buffer, const char *keyring,
                                   GnomeKeyringInfo *info)
{
	gsize op_start;

	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_SET_KEYRING_INFO,
	                                &op_start)) {
		return FALSE;
	}
	if (!gkr_proto_add_utf8_string (buffer, keyring)) {
		return FALSE;
	}
	
	egg_buffer_add_uint32 (buffer, info->lock_on_idle);
	egg_buffer_add_uint32 (buffer, info->lock_timeout);

	if (!gkr_proto_end_operation (buffer, op_start)) {
		return FALSE;
	}

	return TRUE;
}

gboolean
gkr_proto_encode_prepare_environment (EggBuffer *buffer, const gchar **environment)
{
	gsize op_start;
	
	if (!gkr_proto_start_operation (buffer, GNOME_KEYRING_OP_PREPARE_ENVIRONMENT,
	                                &op_start))
		return FALSE;
		
	if (!egg_buffer_add_stringv (buffer, environment))
		return FALSE;

	if (!gkr_proto_end_operation (buffer, op_start))
		return FALSE;

	return TRUE;
}

gboolean
gkr_proto_decode_attribute_list (EggBuffer *buffer, gsize offset, gsize *next_offset,
                                 GnomeKeyringAttributeList **attributes_out)
{
	guint32 list_size;
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;
	char *name;
	guint32 type;
	char *str;
	guint32 val;
	int i;

	attributes = NULL;
	
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &list_size)) {
		goto bail;
	}

	attributes = gnome_keyring_attribute_list_new ();
	for (i = 0; i < list_size; i++) {
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &name)) {
			goto bail;
		}
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &type)) {
			g_free (name);
			goto bail;
		}
		switch (type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &str)) {
				g_free (name);
				goto bail;
			}
			attribute.name = name;
			attribute.type = type;
			attribute.value.string = str;
			g_array_append_val (attributes, attribute);
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			if (!egg_buffer_get_uint32 (buffer, offset, 
			                            &offset, &val)) {
				g_free (name);
				goto bail;
			}
			attribute.name = name;
			attribute.type = type;
			attribute.value.integer = val;
			g_array_append_val (attributes, attribute);
			break;
		default:
			g_free (name);
			goto bail;
		}
	}

	if (attributes_out != NULL) {
		*attributes_out = attributes;
	} else {
		gnome_keyring_attribute_list_free (attributes);
	}
	*next_offset = offset;
	return TRUE;
	
 bail:
	gnome_keyring_attribute_list_free (attributes);
	return FALSE;
}

gboolean
gkr_proto_decode_acl (EggBuffer *buffer, gsize offset, gsize *next_offset,
                      GList **acl_out)
{
	guint32 list_size;
	GList *acl;
	GnomeKeyringAccessControl *ac;
	GnomeKeyringApplicationRef *ref;
	char *display_name;
	char *pathname;
	guint32 types_allowed;
	int i;

	acl = NULL;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &list_size)) {
		goto bail;
	}

	for (i = 0; i < list_size; i++) {
		if (!gkr_proto_get_utf8_string (buffer,
							  offset, &offset,
							  &display_name)) {
			goto bail;
		}
		if (!gkr_proto_get_utf8_string (buffer,
							  offset, &offset,
							  &pathname)) {
			g_free (display_name);
			goto bail;
		}

		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &types_allowed)) {
			g_free (display_name);
			g_free (pathname);
			goto bail;
		}
		ref = g_new0 (GnomeKeyringApplicationRef, 1);
		ref->display_name = display_name;
		ref->pathname = pathname;
		ac = g_new0 (GnomeKeyringAccessControl, 1);
		ac->application = ref;
		ac->types_allowed = types_allowed;
		acl = g_list_append (acl, ac);
	}

	if (acl_out != NULL) {
		*acl_out = acl;
	} else {
		g_list_free (acl);
	}
	*next_offset = offset;
	return TRUE;
	
 bail:
	gnome_keyring_acl_free (acl);
	return FALSE;
}


gboolean
gkr_proto_add_attribute_list (EggBuffer *buffer, GnomeKeyringAttributeList *attributes)
{
	int i;
	GnomeKeyringAttribute *array;

	/* Null attributes = empty attribute array */
	if (!attributes) {
		egg_buffer_add_uint32 (buffer, 0);
		return TRUE;
	}
		
	array = (GnomeKeyringAttribute *)attributes->data;

	i = 0;
	egg_buffer_add_uint32 (buffer, attributes->len);

	for (i = 0; i < attributes->len; i++) {
		if (!gkr_proto_add_utf8_string (buffer, array[i].name)) {
			return FALSE;
		}
		egg_buffer_add_uint32 (buffer, array[i].type);
		switch (array[i].type) {
		case GNOME_KEYRING_ATTRIBUTE_TYPE_STRING:
			if (!gkr_proto_add_utf8_string (buffer, array[i].value.string)) {
				return FALSE;
			}
			break;
		case GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32:
			egg_buffer_add_uint32 (buffer, array[i].value.integer);
			break;
		default:
			g_assert_not_reached ();
		}
	}

	return TRUE;
}

gboolean
gkr_proto_add_acl (EggBuffer *buffer, GList *acl)
{
	int length;
	GnomeKeyringAccessControl *ac;
	GList *tmp;

	length = g_list_length (acl);

	egg_buffer_add_uint32 (buffer, length);

	for (tmp = acl; tmp != NULL; tmp = tmp->next) {
		ac = (GnomeKeyringAccessControl *)tmp->data;
		if (!gkr_proto_add_utf8_string (buffer, ac->application->display_name)) {
			return FALSE;
		}
		if (!gkr_proto_add_utf8_string (buffer, ac->application->pathname)) {
			return FALSE;
		}
		egg_buffer_add_uint32 (buffer, ac->types_allowed);
	}

	return TRUE;
}



gboolean
gkr_proto_decode_result_reply (EggBuffer *buffer, GnomeKeyringResult *result)
{
	gsize offset;
	guint32 res;

	offset = 4;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*result = res;
	
	return TRUE;
}

gboolean
gkr_proto_decode_result_string_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                      char **str)
{
	gsize offset;
	guint32 res;

	offset = 4;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*result = res;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, str)) {
		return FALSE;
	}
	
	return TRUE;
}

gboolean
gkr_proto_decode_result_string_list_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                           GList **list)
{
	gsize offset;
	guint32 res;
	guint32 list_size, i;
	GList *names;
	char *str;

	offset = 4;
	names = NULL;
	
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &list_size)) {
		goto bail;
	}
	
	for (i = 0; i < list_size; i++) {
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &str)) {
			goto bail;
		}
		names = g_list_prepend (names, str);
	}

	*result = res;
	*list = g_list_reverse (names);
	
	return TRUE;

 bail:
	g_list_foreach (names, (GFunc) g_free, NULL);
	g_list_free (names);
	return FALSE;
}

gboolean
gkr_proto_decode_find_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                             GList **list_out)
{
	GList *list;
	gsize offset;
	guint32 res;
	GnomeKeyringFound *found;

	offset = 4;

	*list_out = NULL;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*result = res;
	
	if (res != GNOME_KEYRING_RESULT_OK) {
		return TRUE;
	}

	list = NULL;
	while (offset < buffer->len) {
		found = g_new0 (GnomeKeyringFound, 1);
		list = g_list_prepend (list, found);
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset,
		                                &found->keyring)) {
			goto bail;
		}
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &found->item_id)) {
			goto bail;
		}
		if (!gkr_proto_get_utf8_secret (buffer, offset, &offset,
		                                &found->secret)) {
			goto bail;
		}
		if (!gkr_proto_decode_attribute_list (buffer, offset, &offset,
		                                      &found->attributes)) {
			goto bail;
		}
	}
	
	*list_out = g_list_reverse (list);
	return TRUE;

 bail:
	g_list_foreach (list, (GFunc)gnome_keyring_found_free, NULL);
	return FALSE;
}

gboolean
gkr_proto_decode_find (EggBuffer *buffer, GnomeKeyringItemType *type,
                       GnomeKeyringAttributeList **attributes)
{
	gsize offset;
	GnomeKeyringOpCode op;
	guint32 t;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_FIND) {
		return FALSE;
	}

	offset = 8;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &t)) {
		return FALSE;
	}
	*type = t;
	return gkr_proto_decode_attribute_list (buffer, offset, &offset, attributes);
}

gboolean
gkr_proto_decode_op_string (EggBuffer *buffer, GnomeKeyringOpCode *op_out,
                            char **str1)
{
	gsize offset;
	
	if (str1 != NULL) {
		*str1 = NULL;
	}
	if (!gkr_proto_decode_packet_operation (buffer, op_out)) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, str1)) {
		goto bail;
	}

	return TRUE;
 bail:
	if (str1 != NULL) {
		g_free (*str1);
		*str1 = NULL;
	}
	return FALSE;
}

gboolean
gkr_proto_decode_op_string_int (EggBuffer *buffer, GnomeKeyringOpCode *op_out,
                                char **str1, guint32 *val)
{
	gsize offset;
	
	if (str1 != NULL) {
		*str1 = NULL;
	}
	if (!gkr_proto_decode_packet_operation (buffer, op_out)) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, str1)) {
		goto bail;
	}

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, val)) {
		goto bail;
	}
	
	return TRUE;
 bail:
	if (str1 != NULL) {
		g_free (*str1);
		*str1 = NULL;
	}
	return FALSE;
}

gboolean
gkr_proto_decode_get_item_info (EggBuffer *buffer, GnomeKeyringOpCode *op_out,
                                char **keyring, guint32 *item_id, guint32 *flags)
{
	gsize offset = 8;
	*keyring = NULL;
	if (!gkr_proto_decode_packet_operation (buffer, op_out))
		return FALSE;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring))
		goto bail;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, item_id))
		goto bail;
	if (*op_out == GNOME_KEYRING_OP_GET_ITEM_INFO_FULL) {
		/* Pull in lookup flags/parts, find out which ones */
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, flags))
			goto bail;
	} else {
		/* All parts of the item by default */
		*flags = GNOME_KEYRING_ITEM_INFO_ALL;
	}
	
	return TRUE;
 bail:
	g_free (*keyring);
	*keyring = NULL;
	return FALSE;
}

gboolean
gkr_proto_decode_op_string_secret (EggBuffer *buffer, GnomeKeyringOpCode *op_out,
                                   char **str1, char **str2)
{
	gsize offset;

	if (str1 != NULL) {
		*str1 = NULL;
	}
	if (str2 != NULL) {
		*str2 = NULL;
	}
	if (!gkr_proto_decode_packet_operation (buffer, op_out)) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, str1)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, str2)) {
		goto bail;
	}
	
	return TRUE;
 bail:
	if (str1 != NULL) {
		g_free (*str1);
		*str1 = NULL;
	}
	if (str2 != NULL) {
		g_free (*str2);
		*str2 = NULL;
	}
	return FALSE;
}

gboolean
gkr_proto_decode_op_string_secret_secret (EggBuffer *buffer, GnomeKeyringOpCode *op_out,
                                          char **str1, char **str2, char **str3)
{
	gsize offset;

	if (str1 != NULL) {
		*str1 = NULL;
	}
	if (str2 != NULL) {
		*str2 = NULL;
	}
	if (str3 != NULL) {
		*str3 = NULL;
	}
	if (!gkr_proto_decode_packet_operation (buffer, op_out)) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, str1)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, str2)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, str3)) {
		goto bail;
	}
	
	return TRUE;
 bail:
	if (str1 != NULL) {
		g_free (*str1);
		*str1 = NULL;
	}
	if (str2 != NULL) {
		g_free (*str2);
		*str2 = NULL;
	}
	if (str3 != NULL) {
		g_free (*str3);
		*str3 = NULL;
	}
	return FALSE;
}


gboolean
gkr_proto_decode_get_attributes_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                       GnomeKeyringAttributeList **attributes)
{
	gsize offset;
	guint32 res;

	offset = 4;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*attributes = NULL;
	*result = res;
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!gkr_proto_decode_attribute_list (buffer, offset, &offset, attributes)) {
			return FALSE;
		}
		
	}
		
	return TRUE;
}

gboolean
gkr_proto_decode_get_acl_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                GList **acl)
{
	gsize offset;
	guint32 res;

	offset = 4;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*acl = NULL;
	*result = res;
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!gkr_proto_decode_acl (buffer, offset, &offset, acl)) {
			return FALSE;
		}
		
	}
		
	return TRUE;
}


gboolean
gkr_proto_decode_get_item_info_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                      GnomeKeyringItemInfo      **info_out)
{
	gsize offset;
	guint32 res, type;
	GnomeKeyringItemInfo *info;
	time_t mtime, ctime;
	char *name;
	char *secret;

	info = NULL;
	
	offset = 4;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &type)) {
			return FALSE;
		}
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &name)) {
			return FALSE;
		}
		if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, &secret)) {
			g_free (name);
			return FALSE;
		}
		
		if (!gkr_proto_get_time (buffer, offset, &offset, &mtime)) {
			g_free (name);
			egg_secure_strfree (secret);
			return FALSE;
		}
		if (!gkr_proto_get_time (buffer, offset, &offset, &ctime)) {
			g_free (name);
			egg_secure_strfree (secret);
			return FALSE;
		}
		
		info = g_new (GnomeKeyringItemInfo, 1);
		info->type = type;
		info->display_name = name;
		info->secret = secret;
		info->mtime = mtime;
		info->ctime = ctime;
	}
		
	*result = res;
	*info_out = info;
	
	return TRUE;
}

gboolean
gkr_proto_decode_get_keyring_info_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                         GnomeKeyringInfo **info_out)
{
	gsize offset;
	guint32 res;
	GnomeKeyringInfo *info;
	guint32 lock_on_idle, lock_timeout, is_locked;
	time_t mtime, ctime;

	info = NULL;
	
	offset = 4;
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset,
		                            &lock_on_idle)) {
			return FALSE;
		}
		if (!egg_buffer_get_uint32 (buffer, offset, &offset,
		                            &lock_timeout)) {
			return FALSE;
		}
		if (!gkr_proto_get_time (buffer, offset, &offset, &mtime)) {
			return FALSE;
		}
		if (!gkr_proto_get_time (buffer, offset, &offset, &ctime)) {
			return FALSE;
		}
		if (!egg_buffer_get_uint32 (buffer, offset, &offset,
		                            &is_locked)) {
			return FALSE;
		}
		info = g_new (GnomeKeyringInfo, 1);
		info->lock_on_idle = lock_on_idle;
		info->lock_timeout = lock_timeout;
		info->mtime = mtime;
		info->ctime = ctime;
		info->is_locked = is_locked;
	}
		
	*result = res;
	*info_out = info;
	
	return TRUE;
}

gboolean
gkr_proto_decode_set_item_info (EggBuffer *buffer, char **keyring, guint32 *item_id,
                                GnomeKeyringItemType *type, char **display_name,
                                char **secret)
{
	gsize offset;
	GnomeKeyringOpCode op;
	guint32 typeint;

	*keyring = NULL;
	*display_name = NULL;
	*secret = NULL;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_SET_ITEM_INFO) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, item_id)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &typeint)) {
		goto bail;
	}
	*type = typeint;
	
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, display_name)) {
		goto bail;
	}
	if (!gkr_proto_get_utf8_secret (buffer, offset, &offset, secret)) {
		goto bail;
	}

	return TRUE;
	
 bail:
	g_free (*keyring);
	g_free (*display_name);
	egg_secure_strfree (*secret);
	return FALSE;
}

gboolean
gkr_proto_decode_set_keyring_info (EggBuffer *buffer, char **keyring,
                                   gboolean *lock_on_idle, guint32 *lock_timeout)

{
	gsize offset;
	GnomeKeyringOpCode op;
	guint32 lock_int;

	*keyring = NULL;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_SET_KEYRING_INFO) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &lock_int)) {
		goto bail;
	}
	*lock_on_idle = lock_int;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, lock_timeout)) {
		goto bail;
	}

	return TRUE;
	
 bail:
	g_free (*keyring);
	return FALSE;
}

gboolean
gkr_proto_decode_set_attributes (EggBuffer *buffer, char **keyring,
                                 guint32 *item_id, GnomeKeyringAttributeList **attributes)
{
	gsize offset;
	GnomeKeyringOpCode op;

	*keyring = NULL;
	*attributes = NULL;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_SET_ITEM_ATTRIBUTES) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, item_id)) {
		goto bail;
	}
	
	if (!gkr_proto_decode_attribute_list (buffer, offset, &offset, attributes)) {
		goto bail;
	}

	return TRUE;
	
 bail:
	g_free (*keyring);
	return FALSE;
}


gboolean
gkr_proto_decode_set_acl (EggBuffer *buffer, char **keyring, guint32 *item_id,
                          GList  **acl)
{
	gsize offset;
	GnomeKeyringOpCode op;

	*keyring = NULL;
	*acl = NULL;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op)) {
		return FALSE;
	}
	if (op != GNOME_KEYRING_OP_SET_ITEM_ACL) {
		return FALSE;
	}
	offset = 8;
	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, keyring)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, item_id)) {
		goto bail;
	}
	
	if (!gkr_proto_decode_acl (buffer, offset, &offset, acl)) {
		goto bail;
	}

	return TRUE;
	
 bail:
	g_free (*keyring);
	return FALSE;
}

gboolean
gkr_proto_decode_prepare_environment (EggBuffer *buffer, gchar ***environment)
{
	GnomeKeyringOpCode op;
	gsize offset;
	
	if (!gkr_proto_decode_packet_operation (buffer, &op))
		return FALSE;
	if (op != GNOME_KEYRING_OP_PREPARE_ENVIRONMENT)
		return FALSE;
		
	offset = 8;
	
	if (!egg_buffer_get_stringv (buffer, offset, &offset, environment, g_realloc))
		return FALSE; 
	
	return TRUE;
}

gboolean 
gkr_proto_decode_prepare_environment_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                            char ***environment)
{
	gsize offset;
	guint32 res;

	offset = 4;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res))
		return FALSE;
	*result = res;

	if (res == GNOME_KEYRING_RESULT_OK) {
		if (!egg_buffer_get_stringv (buffer, offset, &offset, environment, g_realloc))
			return FALSE; 
	}		
	
	return TRUE;
}

gboolean
gkr_proto_decode_result_int_list_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                        GList **list)
{
	gsize offset;
	guint32 res, len, i, id;

	*list = NULL;

	offset = 4;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	*result = res;
	
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &len)) {
		return FALSE;
	}
	
	for (i = 0; i < len; i++) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &id)) {
			g_list_free (*list);
			*list = NULL;
			return FALSE;
		}
		*list = g_list_prepend (*list, GUINT_TO_POINTER (id));
		
	}
	*list = g_list_reverse (*list);
	return TRUE;
}

gboolean
gkr_proto_decode_result_integer_reply (EggBuffer *buffer, GnomeKeyringResult *result,
                                       guint32 *integer)
{
	gsize offset;
	guint32 res, val;

	offset = 4;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &res)) {
		return FALSE;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &val)) {
		return FALSE;
	}
	
	*result = res;
	if (integer != NULL) {
		*integer = val;
	}
	
	return TRUE;
}

