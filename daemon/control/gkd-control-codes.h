/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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
 */

#ifndef __GKD_CONTROL_PRIVATE_H__
#define __GKD_CONTROL_PRIVATE_H__

/* All the old op codes, most are no longer used */
enum {
	GNOME_KEYRING_OP_LOCK_ALL,
	GNOME_KEYRING_OP_SET_DEFAULT_KEYRING,
	GNOME_KEYRING_OP_GET_DEFAULT_KEYRING,
	GNOME_KEYRING_OP_LIST_KEYRINGS,
	GNOME_KEYRING_OP_CREATE_KEYRING,
	GNOME_KEYRING_OP_LOCK_KEYRING,
	GNOME_KEYRING_OP_UNLOCK_KEYRING,
	GNOME_KEYRING_OP_DELETE_KEYRING,
	GNOME_KEYRING_OP_GET_KEYRING_INFO,
	GNOME_KEYRING_OP_SET_KEYRING_INFO,
	GNOME_KEYRING_OP_LIST_ITEMS,
	GNOME_KEYRING_OP_FIND,
	GNOME_KEYRING_OP_CREATE_ITEM,
	GNOME_KEYRING_OP_DELETE_ITEM,
	GNOME_KEYRING_OP_GET_ITEM_INFO,
	GNOME_KEYRING_OP_SET_ITEM_INFO,
	GNOME_KEYRING_OP_GET_ITEM_ATTRIBUTES,
	GNOME_KEYRING_OP_SET_ITEM_ATTRIBUTES,
	GNOME_KEYRING_OP_GET_ITEM_ACL,
	GNOME_KEYRING_OP_SET_ITEM_ACL,
	GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD,
	GNOME_KEYRING_OP_SET_DAEMON_DISPLAY,
	GNOME_KEYRING_OP_GET_ITEM_INFO_FULL,
	GNOME_KEYRING_OP_PREPARE_ENVIRONMENT,

	/* Add new ops here */

	GNOME_KEYRING_NUM_OPS
};

/* All the old result codes */
enum {
	GNOME_KEYRING_RESULT_OK,
	GNOME_KEYRING_RESULT_DENIED,
	GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON,
	GNOME_KEYRING_RESULT_ALREADY_UNLOCKED,
	GNOME_KEYRING_RESULT_NO_SUCH_KEYRING,
	GNOME_KEYRING_RESULT_BAD_ARGUMENTS,
	GNOME_KEYRING_RESULT_IO_ERROR,
	GNOME_KEYRING_RESULT_CANCELLED,
	GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS,
	GNOME_KEYRING_RESULT_NO_MATCH
};

#endif /* __GKD_CONTROL_PRIVATE_H__ */