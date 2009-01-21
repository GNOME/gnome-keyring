/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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

#ifndef __GCR_H__
#define __GCR_H__

#include <glib.h>

#ifndef GCR_API_SUBJECT_TO_CHANGE
#error "This API has not yet reached stability." 
#endif 

struct _GP11Slot;

#ifdef UNIMPLEMENTED
enum {
	GCR_INIT_NO_MODULES = 0x01,
};

void                 gcr_initialize                          (guint flags);

void                 gcr_modules_register_loaded             (gpointer funcs);

gboolean             gcr_modules_register_file               (const gchar *module_path,
                                                              GError *error);
#endif /* UNIMPLEMENTED */

#endif /* __GCR_H__ */
