/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#ifndef GCKTIMER_H_
#define GCKTIMER_H_

#include <glib.h>

#include "gck-types.h"

typedef void    (*GckTimerFunc)                (GckTimer *timer,
                                                gpointer user_data); 

GckTimer*       gck_timer_start                (GckModule *module, 
                                                glong when,
                                                GckTimerFunc func, 
                                                gpointer user_data);

void            gck_timer_cancel               (GckTimer *timer);

void            gck_timer_initialize           (void);

void            gck_timer_shutdown             (void);

#endif /* GCKTIMER_H_ */
