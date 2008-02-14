/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-proto.h - helper code for the keyring daemon protocol

   Copyright (C) 2007 Stefan Walter

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
#ifndef GNOME_KEYRING_OPCODES_H
#define GNOME_KEYRING_OPCODES_H

typedef enum {
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
} GnomeKeyringOpCode;

#endif /* GNOME_KEYRING_OPCODES_H */
