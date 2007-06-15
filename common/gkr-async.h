/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-async.h - some daemon async functionality

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#ifndef __GKR_ASYNC_H__
#define __GKR_ASYNC_H__

#include <glib.h>

struct _GkrAsyncCalls;
typedef struct _GkrAsyncCalls GkrAsyncCalls;

struct _GkrAsyncReply;
typedef struct _GkrAsyncReply GkrAsyncReply;

typedef void (*GkrAsyncFunc) (GkrAsyncReply* reply, gpointer message);

/* Called from the helper thread */

gpointer           gkr_async_call               (GkrAsyncCalls* context, 
                                                 GkrAsyncFunc callback,
                                                 gpointer data);

GkrAsyncReply*     gkr_async_call_send          (GkrAsyncCalls* context, 
                                                 GkrAsyncFunc callback,
                                                 gpointer data);

gpointer           gkr_async_call_wait          (GkrAsyncReply* reply);

/* Called on the main thread */

GkrAsyncCalls*     gkr_async_call_new_context   (void);

void               gkr_async_call_free_context  (GkrAsyncCalls* context);

void               gkr_async_call_reply         (GkrAsyncReply* reply,
                                                 gpointer data);

#endif /* __GKR_ASYNC_H__ */
