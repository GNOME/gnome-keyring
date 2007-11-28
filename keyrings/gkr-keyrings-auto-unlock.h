#ifndef GKRKEYRINGSAUTOUNLOCK_H_
#define GKRKEYRINGSAUTOUNLOCK_H_

#include "library/gnome-keyring.h"

gboolean        gkr_keyrings_auto_unlock_check  (void);

void            gkr_keyrings_auto_unlock_save   (GnomeKeyringItemType type, 
                                                 const gchar *display_name, 
                                                 const gchar *secret,
                                                 ...);

const gchar*    gkr_keyrings_auto_unlock_lookup (GnomeKeyringItemType type,
                                                 ...);
                                                 
void            gkr_keyrings_auto_unlock_remove (GnomeKeyringItemType type,
                                                 ...);

#endif /*GKRKEYRINGSAUTOUNLOCK_H_*/
