#ifndef GNOME_KEYRING_DAEMON_H
#define GNOME_KEYRING_DAEMON_H

#include <time.h>
#include <glib.h>

#include "gnome-keyring.h"
#include "gnome-keyring-private.h"

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

typedef struct {
	/* NULL if memory only */
	char *file;
	time_t file_mtime;

	/* If known: */
	char *password;
	gboolean locked;

	/* On disk data: */
	   
	char *keyring_name;
	GList *items;

	time_t ctime;
	time_t mtime;

	gboolean lock_on_idle;
	guint lock_timeout;
} GnomeKeyring;

typedef struct {
	GnomeKeyring *keyring;

	guint32 id;
	
	GnomeKeyringItemType type;

	gboolean locked;

	/* These are hashed if locked, normal if unlocked, encrypted on file: */

	GArray *attributes;

	/* Below is encrypted in file, invalid in memory if locked: */
	
	char *display_name;
	char *secret;
	GList *acl;
	time_t ctime;
	time_t mtime;
} GnomeKeyringItem;

typedef enum {
	GNOME_KEYRING_ACCESS_REQUEST_KEYRING,
	GNOME_KEYRING_ACCESS_REQUEST_ITEM,
	GNOME_KEYRING_ACCESS_REQUEST_NEW_KEYRING_PASSWORD,
	GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING,
} GnomeKeyringAccessRequestType;

typedef struct {
	GnomeKeyringAccessRequestType request_type;
	
	GnomeKeyringAccessType access_type;

	/* Only one is non-NULL */
	GnomeKeyring *keyring;
	GnomeKeyringItem *item;
	
	char *new_keyring;
	/* filled out for password requests */
	char *password;
	
	gboolean granted;
} GnomeKeyringAccessRequest;

typedef struct {
	gboolean (*collect_info) (GString *packet,
				  GList **access_requests);
	gboolean (*execute_op) (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests);
} GnomeKeyringOperationImplementation;

extern GnomeKeyringOperationImplementation keyring_ops[];

typedef void (*GnomeKeyringRequestAccessCallback) (GList *access_requests,
						   gpointer data);

gpointer gnome_keyring_ask      (GList                             *access_requests,
				 GnomeKeyringApplicationRef        *app_ref,
				 GnomeKeyringRequestAccessCallback  callback,
				 gpointer                           data);
void     gnome_keyring_cancel_ask (gpointer                           request);

GList *                    gnome_keyring_access_request_list_copy (GList                     *list);
void                       gnome_keyring_access_request_list_free (GList                     *list);
void                       gnome_keyring_access_request_free      (GnomeKeyringAccessRequest *access_request);
GnomeKeyringAccessRequest *gnome_keyring_access_request_copy      (GnomeKeyringAccessRequest *access_request);

GnomeKeyringApplicationRef *gnome_keyring_application_ref_new_from_pid (pid_t                             pid);
GnomeKeyringApplicationRef *gnome_keyring_application_ref_copy         (const GnomeKeyringApplicationRef *app);
void                        gnome_keyring_application_ref_free         (GnomeKeyringApplicationRef       *app);

void gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac);
void                        gnome_keyring_acl_free                     (GList                            *acl);


void     cleanup_socket_dir   (void);
gboolean create_master_socket (const char **path);

void update_keyrings_from_disk (void);
void save_keyring_to_disk (GnomeKeyring *keyring);
gboolean update_keyring_from_disk (GnomeKeyring *keyring, gboolean force_reload);

GnomeKeyringAttributeList *gnome_keyring_attributes_hash (GnomeKeyringAttributeList *attributes);
GnomeKeyringAccessControl *gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
							     GnomeKeyringAccessType types_allowed);

GnomeKeyringItem * find_item_in_list (GList *list, guint32 id);
GnomeKeyring * find_keyring (const char *name);
void gnome_keyring_item_free (GnomeKeyringItem *item);

GnomeKeyring * gnome_keyring_new (const char *name, const char *path);
GnomeKeyringItem * gnome_keyring_item_new (GnomeKeyring *keyring,
					   GnomeKeyringItemType type);

void gnome_keyring_free (GnomeKeyring *keyring);

char *get_default_keyring_file_for_name (const char *keyring_name);

extern GList *keyrings;
extern GnomeKeyring *session_keyring;

#endif /* GNOME_KEYRING_DAEMON_H */
