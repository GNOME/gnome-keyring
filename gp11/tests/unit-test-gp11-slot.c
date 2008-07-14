
#include <check.h>

#include <glib.h>
#include <string.h>

#include "run-auto-test.h"
#include "gp11-test.h"

static GP11Module *module = NULL;
static GP11Slot *slot = NULL;

DEFINE_SETUP(load_slots)
{
	GError *err = NULL;
	GList *slots;
	
	/* Successful load */
	module = gp11_module_initialize (".libs/libgp11-test-module.so", &err);
	SUCCESS_RES (module, err);
	
	slots = gp11_module_get_slots (module, TRUE);
	fail_if (slots == NULL);
	
	slot = GP11_SLOT (slots->data);
	g_object_ref (slot);
	gp11_list_unref_free (slots);
	
}

DEFINE_TEARDOWN(load_slots)
{
	g_object_unref (slot);
	g_object_unref (module);
}

DEFINE_TEST(slot_info)
{
	GP11SlotInfo *info;
	GP11TokenInfo *token;
	GList *slots, *l;

	slots = gp11_module_get_slots (module, FALSE);
	fail_unless (2 == g_list_length (slots), "wrong number of slots returned");
	fail_unless (GP11_IS_SLOT (slots->data), "missing slot one");
	fail_unless (GP11_IS_SLOT (slots->next->data), "missing slot two");
	
	for (l = slots; l; l = g_list_next (l)) {
		info = gp11_slot_get_info (GP11_SLOT (l->data));
		fail_unless (info != NULL, "no slot info");

		fail_unless (strcmp("TEST MANUFACTURER", info->manufacturer_id) == 0);
		fail_unless (strcmp("TEST SLOT", info->slot_description) == 0);
		fail_unless (55 == info->hardware_version_major);
		fail_unless (155 == info->hardware_version_minor);
		fail_unless (65 == info->firmware_version_major);
		fail_unless (165 == info->firmware_version_minor);
	
		gp11_slot_info_free (info);
		
		if (info->flags & CKF_TOKEN_PRESENT) {		
			token = gp11_slot_get_token_info (slot);
			fail_if (token == NULL, "no token info");

			fail_unless (strcmp ("TEST MANUFACTURER", token->manufacturer_id) == 0);
			fail_unless (strcmp ("TEST LABEL", token->label) == 0);
			fail_unless (strcmp ("TEST MODEL", token->model) == 0);
			fail_unless (strcmp ("TEST SERIAL", token->serial_number) == 0);
			fail_unless (1 == token->max_session_count);
			fail_unless (2 == token->session_count);
			fail_unless (3 == token->max_rw_session_count);
			fail_unless (4 == token->rw_session_count);
			fail_unless (5 == token->max_pin_len);
			fail_unless (6 == token->min_pin_len);
			fail_unless (7 == token->total_public_memory);
			fail_unless (8 == token->free_public_memory);
			fail_unless (9 == token->total_private_memory);
			fail_unless (10 == token->free_private_memory);
			fail_unless (75 == token->hardware_version_major);
			fail_unless (175 == token->hardware_version_minor);
			fail_unless (85 == token->firmware_version_major);
			fail_unless (185 == token->firmware_version_minor);
			fail_unless (927645599 == token->utc_time);
			
			gp11_token_info_free (token);
		}
	}
	
	gp11_list_unref_free (slots);
}

DEFINE_TEST(slot_props)
{
	GP11Module *mod;
	CK_SLOT_ID slot_id;
	
	g_object_get (slot, "module", &mod, "handle", &slot_id, NULL);
	fail_unless (mod == module);
	fail_unless (slot_id == 52);

	g_object_unref (mod);
}

DEFINE_TEST(slot_mechanisms)
{
	GSList *mechs, *l;
	GP11MechanismInfo *info;
	
	mechs = gp11_slot_get_mechanisms (slot);
	fail_unless (2 == g_slist_length (mechs), "wrong number of mech types returned");

	for (l = mechs; l; l = g_slist_next (l)) {
		
		info = gp11_slot_get_mechanism_info (slot, GPOINTER_TO_UINT (l->data));
		fail_unless (info != NULL, "no mech info returned");
		
		gp11_mechanism_info_free (info);
	}
	
	g_slist_free (mechs);
}

