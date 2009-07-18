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

#ifndef __GCK_MODULE_H__
#define __GCK_MODULE_H__

#include <glib-object.h>

#include "pkcs11/pkcs11.h"

#include "gck-factory.h"
#include "gck-types.h"

#define GCK_TYPE_MODULE               (gck_module_get_type ())
#define GCK_MODULE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_MODULE, GckModule))
#define GCK_MODULE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_MODULE, GckModuleClass))
#define GCK_IS_MODULE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_MODULE))
#define GCK_IS_MODULE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_MODULE))
#define GCK_MODULE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_MODULE, GckModuleClass))

typedef struct _GckModuleClass GckModuleClass;
typedef struct _GckModulePrivate GckModulePrivate;
    
struct _GckModule {
	GObject parent;
	CK_FUNCTION_LIST pkcs11_funcs;
	GckModulePrivate *pv;
};

struct _GckModuleClass {
	GObjectClass parent_class;
	
	/* virtual methods */

	void (*parse_argument) (GckModule *self, const gchar *name, const gchar *value);
	
	const CK_SLOT_INFO* (*get_slot_info) (GckModule *self);

	const CK_TOKEN_INFO* (*get_token_info) (GckModule *self);

	CK_RV (*refresh_token) (GckModule *self);
	
	void (*store_token_object) (GckModule *self, GckTransaction *transaction, GckObject *object);
	
	void (*remove_token_object) (GckModule *self, GckTransaction *transaction, GckObject *object);

	CK_RV (*login_change) (GckModule *self, CK_SLOT_ID slot_id, 
	                       CK_UTF8CHAR_PTR old_pin, CK_ULONG n_old_pin,
	                       CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin);

	CK_RV (*login_user) (GckModule *self, CK_SLOT_ID slot_id, 
	                     CK_UTF8CHAR_PTR pin, CK_ULONG n_pin);

	CK_RV (*logout_user) (GckModule *self, CK_SLOT_ID slot_id);

	CK_RV (*login_so) (GckModule *self, CK_SLOT_ID slot_id, 
	                   CK_UTF8CHAR_PTR pin, CK_ULONG n_pin);

	CK_RV (*logout_so) (GckModule *self, CK_SLOT_ID slot_id);
};

/* 
 * The PKCS#11 module is created by the following code in a header file:
 * 
 *     #include "gck-module.h"
 *     GCK_DECLARE_MODULE(my_module);
 * 
 * And the following code in a source file:
 * 
 *     #include "gck-module-ep.h"
 *     GCK_DEFINE_MODULE(my_module, MY_TYPE_MODULE)
 *     
 */

#define GCK_DECLARE_MODULE(prefix) \
	extern const CK_FUNCTION_LIST_PTR prefix ## _function_list

#define GCK_DEFINE_MODULE(prefix, type) \
	static GckModule* gck_module_instantiate (CK_C_INITIALIZE_ARGS_PTR args, GMutex* mutex) \
		{ return g_object_new ((type), "initialize-args", args, "mutex", mutex, NULL); } \
	const CK_FUNCTION_LIST_PTR prefix ## _function_list = &gck_module_function_list;

GType                  gck_module_get_type                        (void);

GckManager*            gck_module_get_manager                     (GckModule *self);

gboolean               gck_module_get_write_protected             (GckModule *self);

CK_ULONG               gck_module_next_handle                     (GckModule *self);

GckSession*            gck_module_lookup_session                  (GckModule *self,
                                                                   CK_SESSION_HANDLE handle);

CK_RV                  gck_module_login_change                    (GckModule *self, 
                                                                   CK_SLOT_ID slot_id, 
                                                                   CK_UTF8CHAR_PTR old_pin, 
                                                                   CK_ULONG n_old_pin,
                                                                   CK_UTF8CHAR_PTR new_pin, 
                                                                   CK_ULONG n_new_pin);

CK_RV                  gck_module_login_user                      (GckModule *self,
                                                                   CK_SLOT_ID slot_id,
                                                                   CK_UTF8CHAR_PTR pin,
                                                                   CK_ULONG n_pin);

CK_RV                  gck_module_logout_user                     (GckModule *self,
                                                                   CK_SLOT_ID slot_id);

CK_RV                  gck_module_login_so                        (GckModule *self,
                                                                   CK_SLOT_ID slot_id,
                                                                   CK_UTF8CHAR_PTR pin,
                                                                   CK_ULONG n_pin);

CK_RV                  gck_module_logout_so                       (GckModule *self,
                                                                   CK_SLOT_ID slot_id);

CK_RV                  gck_module_refresh_token                   (GckModule *self);

void                   gck_module_store_token_object              (GckModule *self,
                                                                   GckTransaction *transaction,
                                                                   GckObject *object);

void                   gck_module_remove_token_object             (GckModule *self,
                                                                   GckTransaction *transaction,
                                                                   GckObject *object);

GckFactory             gck_module_find_factory                    (GckModule *self,
                                                                   CK_ATTRIBUTE_PTR attrs,
                                                                   CK_ULONG n_attrs);

void                   gck_module_register_factory                (GckModule *self, 
                                                                   GckFactoryInfo *factory);

CK_RV                  gck_module_C_GetInfo                       (GckModule *self, 
                                                                   CK_INFO_PTR info);

CK_RV                  gck_module_C_GetSlotList                   (GckModule *self, 
                                                                   CK_BBOOL token_present, 
                                                                   CK_SLOT_ID_PTR slot_list, 
                                                                   CK_ULONG_PTR count);

CK_RV                  gck_module_C_GetSlotInfo                   (GckModule *self, 
                                                                   CK_SLOT_ID id, 
                                                                   CK_SLOT_INFO_PTR info);

CK_RV                  gck_module_C_GetTokenInfo                  (GckModule *self, 
                                                                   CK_SLOT_ID id, 
                                                                   CK_TOKEN_INFO_PTR info);

CK_RV                  gck_module_C_GetMechanismList              (GckModule *self, 
                                                                   CK_SLOT_ID id, 
                                                                   CK_MECHANISM_TYPE_PTR mech_list, 
                                                                   CK_ULONG_PTR count);

CK_RV                  gck_module_C_GetMechanismInfo              (GckModule *self, 
                                                                   CK_SLOT_ID id, 
                                                                   CK_MECHANISM_TYPE type, 
                                                                   CK_MECHANISM_INFO_PTR info);

CK_RV                  gck_module_C_InitToken                     (GckModule *self,
                                                                   CK_SLOT_ID id, 
                                                                   CK_UTF8CHAR_PTR pin, 
                                                                   CK_ULONG pin_len, 
                                                                   CK_UTF8CHAR_PTR label);

CK_RV                  gck_module_C_OpenSession                   (GckModule *self, 
                                                                   CK_SLOT_ID id, 
                                                                   CK_FLAGS flags, 
                                                                   CK_VOID_PTR user_data, 
                                                                   CK_NOTIFY callback, 
                                                                   CK_SESSION_HANDLE_PTR session);

CK_RV                  gck_module_C_CloseSession                  (GckModule *self,
                                                                   CK_SESSION_HANDLE session);

CK_RV                  gck_module_C_CloseAllSessions              (GckModule *self, 
                                                                   CK_SLOT_ID id);

CK_RV                  gck_module_C_InitPIN                       (GckModule* self, 
                                                                   CK_SESSION_HANDLE session,
                                                                   CK_UTF8CHAR_PTR pin,
                                                                   CK_ULONG pin_len);

CK_RV                  gck_module_C_SetPIN                        (GckModule* self,
                                                                   CK_SESSION_HANDLE session,
                                                                   CK_UTF8CHAR_PTR old_pin,
                                                                   CK_ULONG old_pin_len, 
                                                                   CK_UTF8CHAR_PTR new_pin, 
                                                                   CK_ULONG new_pin_len);

CK_RV                  gck_module_C_Login                         (GckModule *self, 
                                                                   CK_SESSION_HANDLE session, 
                                                                   CK_USER_TYPE user_type,
                                                                   CK_UTF8CHAR_PTR pin, 
                                                                   CK_ULONG pin_len);

CK_RV                  gck_module_C_Logout                        (GckModule *self, 
                                                                   CK_SESSION_HANDLE session);

#endif /* __GCK_MODULE_H__ */
