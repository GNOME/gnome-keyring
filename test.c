#include "gnome-keyring.h"

static GMainLoop *loop = NULL;


static void
locked_all  (GnomeKeyringResult result,
	     gpointer           data)
{
	g_print ("lock_all: %d\n", result);
	g_main_loop_quit (loop);
}

static void
lock_all (void)
{
	gpointer req;
	
	req = gnome_keyring_lock_all (locked_all, NULL, NULL);
	g_main_loop_run (loop);
}

#if 0
static void
found_items (GnomeKeyringResult result,
	    GList *found_items,
	    gpointer data)
{
	g_print ("found items: res: %d nr items: %d\n", result, g_list_length (found_items));

	if (found_items != NULL) {
		GnomeKeyringFound *found = found_items->data;
		
		g_print ("Found item: keyring=%s, id=%d, secret='%s'\n", found->keyring, found->item_id, found->secret); 
		
	}
	
	g_main_loop_quit (loop); 
}
#endif

static void
created_item  (GnomeKeyringResult result,
	       guint32            id,
	       gpointer           data)
{
	g_print ("created item: res: %d id: %d\n", result, id);

	g_main_loop_quit (loop);
}


static void
create_item (void)
{
	gpointer req;
	GnomeKeyringAttributeList *attributes;
	GnomeKeyringAttribute attribute;

	attribute.name = "name";
	attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attribute.value.string = "test item";
	
	attributes = gnome_keyring_attribute_list_new ();
	g_array_append_val (attributes, attribute);
	
	req = gnome_keyring_item_create ("default",
					 GNOME_KEYRING_ITEM_NOTE,
					 "test note",
					 attributes,
					 "secret text",
					 created_item, NULL, NULL);
	g_main_loop_run (loop);
}


static void
created_keyring  (GnomeKeyringResult result,
		  gpointer           data)
{
	g_print ("created_keyring: %d\n", result);
	g_main_loop_quit (loop);
}

static void
create_keyring (void)
{
	gpointer req;

	req = gnome_keyring_create ("alextest",
				    NULL, 
				    created_keyring, NULL, NULL);
	g_main_loop_run (loop);
}

static void
set_default_cb  (GnomeKeyringResult result,
		 gpointer           data)
{
	g_print ("set default: %d\n", result);
	g_main_loop_quit (loop);
}

static void
set_default (void)
{
	gpointer req;

	req = gnome_keyring_set_default_keyring ("alextest",
						 set_default_cb, NULL, NULL);
	g_main_loop_run (loop);
}

int
main (int argc, char *argv[])
{
	char arg;

	loop = g_main_loop_new (NULL, FALSE);
	
	arg = 0;
	if (argc >= 2) {
		arg = argv[1][0];
	}

	if (arg == 'l') {
		lock_all ();
	} else if (arg == 'c') {
		create_item ();
	} else if (arg == 'k') {
		create_keyring ();
	} else if (arg == 'd') {
		set_default ();
	} else {
		g_print ("unsupported test\n");
	}
	
	
	return 0;
}
