/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef GKRPKCS11DAEMON_H_
#define GKRPKCS11DAEMON_H_

#include <glib.h>

gboolean      gkr_pkcs11_daemon_initialize       (void);

gboolean      gkr_pkcs11_daemon_startup_pkcs11   (void);

gboolean      gkr_pkcs11_daemon_startup_ssh      (void);

#endif /* GKRPKCS11DAEMON_H_ */
