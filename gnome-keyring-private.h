#ifndef GNOME_KEYRING_PRIVATE_H
#define GNOME_KEYRING_PRIVATE_H

#include "gnome-keyring.h"

struct GnomeKeyringApplicationRef {
	char *display_name;
	char *pathname;
};

typedef enum {
	GNOME_KEYRING_ACCESS_READ = 1<<0,
	GNOME_KEYRING_ACCESS_WRITE = 1<<1,
	GNOME_KEYRING_ACCESS_REMOVE = 1<<2
} GnomeKeyringAccessType;

struct GnomeKeyringAccessControl {
	GnomeKeyringApplicationRef *application; /* null for all */
	GnomeKeyringAccessType types_allowed;
};

struct GnomeKeyringInfo {
	gboolean lock_on_idle;
	guint32 lock_timeout;
	time_t mtime;
	time_t ctime;
	gboolean is_locked;
};

struct GnomeKeyringItemInfo {
	GnomeKeyringItemType type;
	char *display_name;
	char *secret;
	time_t mtime;
	time_t ctime;
};

typedef enum {
	GNOME_KEYRING_ASK_RESPONSE_FAILURE,
	GNOME_KEYRING_ASK_RESPONSE_DENY,
	GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE,
	GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER,
} GnomeKeyringAskResponse;


#endif /* GNOME_KEYRING_PRIVATE_H */
