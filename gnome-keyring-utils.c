#include "config.h"

#include <string.h>
#include <glib.h>

#include "gnome-keyring-private.h"

/* Functions used by both the library and the daemon */

void
gnome_keyring_free_password (char *str)
{
	if (str != NULL) {
		memset (str, 0, strlen (str));
		g_free  (str);
	}
}


void
gnome_keyring_found_free (GnomeKeyringFound *found)
{
	g_free (found->keyring);
	g_free (found->secret);
	gnome_keyring_attribute_list_free (found->attributes);
	g_free (found);
}

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

void
gnome_keyring_info_free (GnomeKeyringInfo *keyring_info)
{
	g_free (keyring_info);
}

GnomeKeyringInfo *
gnome_keyring_info_copy (GnomeKeyringInfo *keyring_info)
{
	GnomeKeyringInfo *copy;

	copy = g_new (GnomeKeyringInfo, 1);
	memcpy (copy, keyring_info, sizeof (GnomeKeyringInfo));
	
	return copy;
}


void
gnome_keyring_item_info_free (GnomeKeyringItemInfo *item_info)
{
	g_free (item_info->display_name);
	if (item_info->secret != NULL) {
		/* clear the secret on free */
		memset (item_info->secret, 0, strlen (item_info->secret));
		g_free (item_info->secret);
	}
	g_free (item_info);
}

GnomeKeyringItemInfo *
gnome_keyring_item_info_copy (GnomeKeyringItemInfo *item_info)
{
	GnomeKeyringItemInfo *copy;

	copy = g_new (GnomeKeyringItemInfo, 1);
	memcpy (copy, item_info, sizeof (GnomeKeyringItemInfo));

	copy->display_name = g_strdup (copy->display_name);
	copy->secret = g_strdup (copy->secret);
	
	return copy;
}

