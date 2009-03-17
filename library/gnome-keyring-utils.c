/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-proto.c - shared utility functions

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
#include <glib.h>
#include <glib/gi18n-lib.h>

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"
#include "gnome-keyring-memory.h"

#include "egg/egg-secure-memory.h"

/**
 * SECTION:gnome-keyring-result
 * @title: Result Codes
 * @short_description: Gnome Keyring Result Codes
 * 
 * <para>
 * Result codes used through out GNOME Keyring. Additional result codes may be 
 * added from time to time and these should be handled gracefully.
 * </para>
 */

/* Functions used by both the library and the daemon */

/* 
 * A list of all the environment variables the daemon can
 * possibly send out when it starts. 
 */
const gchar *GNOME_KEYRING_OUT_ENVIRONMENT[] = {
	"SSH_AUTH_SOCK",
	"GNOME_KEYRING_SOCKET",
	"GNOME_KEYRING_PID",
	"SSH_AGENT_PID",
	NULL
};

/*
 * A list of all the environment variables the daemon 
 * is interested in from clients if it was started 
 * early before these environment variables were set.
 */
const gchar *GNOME_KEYRING_IN_ENVIRONMENT[] = {
	"DISPLAY",
	"DBUS_SESSION_BUS_ADDRESS",
	"DESKTOP_AUTOSTART_ID",
	"ICEAUTHORITY",
	"LANG",
	"XAUTHORITY",
	"XAUTHLOCALHOSTNAME",
	"XDG_SESSION_COOKIE",
	"LOGNAME",
	"USERNAME",
	NULL
};

gchar** 
gnome_keyring_build_environment (const gchar **names)
{
	GArray *array = g_array_sized_new (TRUE, TRUE, sizeof (gchar*), 8);
	const gchar *value;
	const gchar **name;
	gchar *env;
	
	/* Transform them into NAME=VALUE pairs */
	for (name = names; *name; ++name) {
		value = g_getenv (*name);
		if (value) {
			env = g_strdup_printf ("%s=%s", *name, value);
			g_array_append_val (array, env);
		}
	}

	return (gchar**)g_array_free (array, FALSE);
}

void 
gnome_keyring_apply_environment (gchar **envp)
{
	gchar **e, **parts;
	
	g_return_if_fail (envp);
	
	for (e = envp; *e; ++e) {
		parts = g_strsplit (*e, "=", 2);
		if (parts && parts[0] && parts[1])
			g_setenv (parts[0], parts[1], TRUE);
		g_strfreev (parts);
	}
}

/**
 * gnome_keyring_free_password:
 * @password: the password to be freed
 *
 * Clears the memory used by password by filling with '\0' and frees the memory
 * after doing this. You should use this function instead of g_free() for
 * secret information.
 */
void
gnome_keyring_free_password (gchar *password)
{
	egg_secure_strfree (password);
}

/**
 * gnome_keyring_string_list_free:
 * @strings: A %GList of string pointers. 
 * 
 * Free a list of string pointers.
 */
void 
gnome_keyring_string_list_free (GList *strings)
{
	g_list_foreach (strings, (GFunc) g_free, NULL);
	g_list_free (strings);
}

/**
 * gnome_keyring_result_to_message:
 * @res: A #GnomeKeyringResult
 * 
 * The #GNOME_KEYRING_RESULT_OK and #GNOME_KEYRING_RESULT_CANCELLED
 * codes will return an empty string. 
 * 
 * Note that there are some results for which the application will need to 
 * take appropriate action rather than just display an error message to 
 * the user.
 * 
 * Return value: a string suitable for display to the user for a given 
 * #GnomeKeyringResult, or an empty string if the message wouldn't make 
 * sense to a user.
 **/
const gchar* 
gnome_keyring_result_to_message (GnomeKeyringResult res)
{
	switch (res) {
		
	/* If the caller asks for messages for these, they get what they deserve */
	case GNOME_KEYRING_RESULT_OK:
	case GNOME_KEYRING_RESULT_CANCELLED:
		return "";
		
	/* Valid displayable error messages */
	case GNOME_KEYRING_RESULT_DENIED:
		return _("Access Denied");
	case GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON:
		return _("The gnome-keyring-daemon application is not running.");
	case GNOME_KEYRING_RESULT_IO_ERROR:
		return _("Error communicating with gnome-keyring-daemon");
	case GNOME_KEYRING_RESULT_ALREADY_EXISTS:
		return _("A keyring with that name already exists");	
	case GNOME_KEYRING_RESULT_BAD_ARGUMENTS:
		return _("Programmer error: The application sent invalid data.");
	case GNOME_KEYRING_RESULT_NO_MATCH:
		return _("No matching results"); 
	case GNOME_KEYRING_RESULT_NO_SUCH_KEYRING:
		return _("A keyring with that name does not exist.");
	
	/* 
	 * This would be a dumb message to display to the user, we never return 
	 * this from the daemon, only here for compatibility 
	 */
	case GNOME_KEYRING_RESULT_ALREADY_UNLOCKED:
		return _("The keyring has already been unlocked.");
	
	default:
		g_return_val_if_reached (NULL);	
	};
}


/**
 * gnome_keyring_found_free():
 * @found: a #GnomeKeyringFound
 * 
 * Free the memory used by a #GnomeKeyringFound item.
 *
 * You usually want to use gnome_keyring_found_list_free() on the list of
 * results.
 */
void
gnome_keyring_found_free (GnomeKeyringFound *found)
{
	g_free (found->keyring);
	gnome_keyring_free_password (found->secret);
	gnome_keyring_attribute_list_free (found->attributes);
	g_free (found);
}

/**
 * gnome_keyring_found_list_free:
 * @found_list: a #GList of #GnomeKeyringFound
 *
 * Free the memory used by the #GnomeKeyringFound items in @found_list.
 */
void
gnome_keyring_found_list_free (GList *found_list)
{
	g_list_foreach (found_list, (GFunc) gnome_keyring_found_free, NULL);
	g_list_free (found_list);
}

/**
 * SECTION:gnome-keyring-attributes
 * @title: Item Attributes
 * @short_description: Attributes of individual keyring items.
 * 
 * Attributes allow various other pieces of information to be associated with an item. 
 * These can also be used to search for relevant items. Use gnome_keyring_item_get_attributes() 
 * or gnome_keyring_item_set_attributes().
 * 
 * Each attribute has either a string, or unsigned integer value.
 */

/**
 * gnome_keyring_attribute_list_append_string:
 * @attributes: A #GnomeKeyringAttributeList
 * @name: The name of the new attribute
 * @value: The value to store in @attributes
 *
 * Store a key-value-pair with a string value in @attributes.
 */
void
gnome_keyring_attribute_list_append_string (GnomeKeyringAttributeList *attributes,
					    const char *name, const char *value)
{
	GnomeKeyringAttribute attribute;

	attribute.name = g_strdup (name);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = g_strdup (value);
	
	g_array_append_val (attributes, attribute);
}

/**
 * gnome_keyring_attribute_list_append_uint32:
 * @attributes: A #GnomeKeyringAttributeList
 * @name: The name of the new attribute
 * @value: The value to store in @attributes
 *
 * Store a key-value-pair with an unsigned 32bit number value in @attributes.
 */
void
gnome_keyring_attribute_list_append_uint32 (GnomeKeyringAttributeList *attributes,
					    const char *name, guint32 value)
{
	GnomeKeyringAttribute attribute;
	
	attribute.name = g_strdup (name);
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attribute.value.integer = value;
	g_array_append_val (attributes, attribute);
}

/**
 * gnome_keyring_attribute_list_free:
 * @attributes: A #GnomeKeyringAttributeList
 *
 * Free the memory used by @attributes.
 * 
 * If a %NULL pointer is passed, it is ignored.
 **/
void
gnome_keyring_attribute_list_free (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	int i;

	if (attributes == NULL) {
		return;
	}

	array = (GnomeKeyringAttribute *)attributes->data;
	for (i = 0; i < attributes->len; i++) {
		g_free (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			g_free (array[i].value.string);
		}
	}
	
	g_array_free (attributes, TRUE);
}

/**
 * gnome_keyring_attribute_list_copy:
 * @attributes: A #GnomeKeyringAttributeList to copy.
 * 
 * Copy a list of item attributes.
 * 
 * Return value: The new #GnomeKeyringAttributeList
 **/
GnomeKeyringAttributeList *
gnome_keyring_attribute_list_copy (GnomeKeyringAttributeList *attributes)
{
	GnomeKeyringAttribute *array;
	GnomeKeyringAttributeList *copy;
	int i;

	if (attributes == NULL) {
		return NULL;
	}

	copy = g_array_sized_new (FALSE, FALSE, sizeof (GnomeKeyringAttribute), attributes->len);
	
	copy->len = attributes->len;
	memcpy (copy->data, attributes->data, sizeof (GnomeKeyringAttribute) * attributes->len);
	
	array = (GnomeKeyringAttribute *)copy->data;
	for (i = 0; i < copy->len; i++) {
		array[i].name = g_strdup (array[i].name);
		if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
			array[i].value.string = g_strdup (array[i].value.string);
		}
	}
	return copy;
}

/**
 * SECTION:gnome-keyring-keyring-info
 * @title: Keyring Info
 * @short_description: Keyring Information
 * 
 * Use gnome_keyring_get_info() or gnome_keyring_get_info_sync() to get a #GnomeKeyringInfo
 * pointer to use with these functions.
 */

/**
 * gnome_keyring_info_free:
 * @keyring_info: The keyring info to free.
 * 
 * Free a #GnomeKeyringInfo object. If a %NULL pointer is passed
 * nothing occurs. 
 */
void
gnome_keyring_info_free (GnomeKeyringInfo *keyring_info)
{
	g_free (keyring_info);
}

/**
 * SECTION:gnome-keyring-item-info
 * @title: Item Information
 * @short_description: Keyring Item Info
 * 
 * #GnomeKeyringItemInfo represents the basic information about a keyring item.
 * Use gnome_keyring_item_get_info() or gnome_keyring_item_set_info().
 */

/**
 * gnome_keyring_info_copy:
 * @keyring_info: The keyring info to copy.
 *
 * Copy a #GnomeKeyringInfo object. 
 * 
 * Return value: The newly allocated #GnomeKeyringInfo. This must be freed with 
 * gnome_keyring_info_free()
 */
GnomeKeyringInfo *
gnome_keyring_info_copy (GnomeKeyringInfo *keyring_info)
{
	GnomeKeyringInfo *copy;

	copy = g_new (GnomeKeyringInfo, 1);
	memcpy (copy, keyring_info, sizeof (GnomeKeyringInfo));
	
	return copy;
}

/**
 * gnome_keyring_item_info_free:
 * @item_info: The keyring item info pointer.
 * 
 * Free the #GnomeKeyringItemInfo object. 
 * 
 * A %NULL pointer may be passed, in which case it will be ignored.
 **/
void
gnome_keyring_item_info_free (GnomeKeyringItemInfo *item_info)
{
	if (item_info != NULL) {
		g_free (item_info->display_name);
		gnome_keyring_free_password (item_info->secret);
		g_free (item_info);
	}
}

/**
 * gnome_keyring_item_info_new:
 * 
 * Create a new #GnomeKeyringItemInfo object.
 * Free the #GnomeKeyringItemInfo object. 
 * 
 * Return value: A keyring item info pointer.
 **/
GnomeKeyringItemInfo *
gnome_keyring_item_info_new (void)
{
	GnomeKeyringItemInfo *info;

	info = g_new0 (GnomeKeyringItemInfo, 1);

	info->type = GNOME_KEYRING_ITEM_NO_TYPE;
	
	return info;
}

/**
 * gnome_keyring_item_info_copy:
 * @item_info: A keyring item info pointer.
 * 
 * Copy a #GnomeKeyringItemInfo object.
 * 
 * Return value: A keyring item info pointer.
 **/
GnomeKeyringItemInfo *
gnome_keyring_item_info_copy (GnomeKeyringItemInfo *item_info)
{
	GnomeKeyringItemInfo *copy;

	copy = g_new (GnomeKeyringItemInfo, 1);
	memcpy (copy, item_info, sizeof (GnomeKeyringItemInfo));

	copy->display_name = g_strdup (copy->display_name);
	copy->secret = egg_secure_strdup (copy->secret);
	
	return copy;
}

/**
 * gnome_keyring_application_ref_new:
 * 
 * Create a new application reference.
 * 
 * Return value: A new #GnomeKeyringApplicationRef pointer.
 **/
GnomeKeyringApplicationRef *
gnome_keyring_application_ref_new (void)
{
	GnomeKeyringApplicationRef *app_ref;

	app_ref = g_new0 (GnomeKeyringApplicationRef, 1);

	return app_ref;
}

/**
 * gnome_keyring_application_ref_free:
 * @app: A #GnomeKeyringApplicationRef pointer
 * 
 * Free an application reference.
 **/
void
gnome_keyring_application_ref_free (GnomeKeyringApplicationRef *app)
{
	if (app) {
		g_free (app->display_name);
		g_free (app->pathname);
		g_free (app);
	}
}

/**
 * gnome_keyring_application_ref_copy:
 * @app: A #GnomeKeyringApplicationRef pointer
 * 
 * Copy an application reference.
 * 
 * Return value: A new #GnomeKeyringApplicationRef pointer.
 **/
GnomeKeyringApplicationRef *
gnome_keyring_application_ref_copy (const GnomeKeyringApplicationRef *app)
{
	GnomeKeyringApplicationRef *copy;

	copy = g_new (GnomeKeyringApplicationRef, 1);
	copy->display_name = g_strdup (app->display_name);
	copy->pathname = g_strdup (app->pathname);

	return copy;
}

/**
 * gnome_keyring_access_control_new:
 * @application: A #GnomeKeyringApplicationRef pointer
 * @types_allowed: Access types allowed.
 * 
 * Create a new access control for an item. Combine the various access
 * rights allowed.
 * 
 * Return value: The new #GnomeKeyringAccessControl pointer. Use 
 * gnome_keyring_access_control_free() to free the memory.
 **/
GnomeKeyringAccessControl *
gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
                                  GnomeKeyringAccessType types_allowed)
{
	GnomeKeyringAccessControl *ac;
	ac = g_new (GnomeKeyringAccessControl, 1);

	ac->application = gnome_keyring_application_ref_copy (application);
	ac->types_allowed = types_allowed;

	return ac;
}

/**
 * gnome_keyring_access_control_free:
 * @ac: A #GnomeKeyringAccessControl pointer
 *
 * Free an access control for an item. 
 **/
void
gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac)
{
	gnome_keyring_application_ref_free (ac->application);
	g_free (ac);
}

/**
 * gnome_keyring_access_control_copy:
 * @ac: A #GnomeKeyringAcessControl pointer
 * 
 * Copy an access control for an item.
 * 
 * Return value: The new #GnomeKeyringAccessControl pointer. Use 
 * gnome_keyring_access_control_free() to free the memory.
 **/
GnomeKeyringAccessControl *
gnome_keyring_access_control_copy (GnomeKeyringAccessControl *ac)
{
	GnomeKeyringAccessControl *ret;

	ret = gnome_keyring_access_control_new (gnome_keyring_application_ref_copy (ac->application), ac->types_allowed);

	return ret;
}

/**
 * gnome_keyring_acl_copy:
 * @list: A list of #GnomeKeyringAccessControl pointers.
 * 
 * Copy an access control list.
 * 
 * Return value: A new list of #GnomeKeyringAccessControl items. Use 
 * gnome_keyring_acl_free() to free the memory.
 */
GList *
gnome_keyring_acl_copy (GList *list)
{
	GList *ret, *l;

	ret = g_list_copy (list);
	for (l = ret; l != NULL; l = l->next) {
		l->data = gnome_keyring_access_control_copy (l->data);
	}

	return ret;
}

/**
 * gnome_keyring_acl_free:
 * @acl: A list of #GnomeKeyringAccessControl pointers.
 * 
 * Free an access control list.
 */
void
gnome_keyring_acl_free (GList *acl)
{
	g_list_foreach (acl, (GFunc)gnome_keyring_access_control_free, NULL);
	g_list_free (acl);
}

