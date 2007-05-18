#ifndef __GKR_ASK_REQUEST_H__
#define __GKR_ASK_REQUEST_H__

#include <glib-object.h>

G_BEGIN_DECLS

typedef enum {
	GKR_ASK_RESPONSE_FAILURE                = -1, 
	GKR_ASK_RESPONSE_NONE                   = 0,
	GKR_ASK_RESPONSE_DENY,
	GKR_ASK_RESPONSE_ALLOW,
	GKR_ASK_RESPONSE_ALLOW_FOREVER
} GkrAskResponse;

typedef enum {
	GKR_ASK_REQUEST_PASSWORD                = 0x0001,
	GKR_ASK_REQUEST_CONFIRM_PASSWORD        = 0x0002,
	GKR_ASK_REQUEST_ORIGINAL_PASSWORD       = 0x0004,
	
	GKR_ASK_REQUEST_OK_BUTTON               = 0x0100,
	GKR_ASK_REQUEST_CANCEL_BUTTON           = 0x0200,
	GKR_ASK_REQUEST_ALLOW_BUTTON            = 0x1000,
	GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON    = 0x2000,
	GKR_ASK_REQUEST_DENY_BUTTON             = 0x4000
} GkrAskRequestFlags;

typedef enum {
	GKR_ASK_DONT_CARE                 = 0,
	GKR_ASK_STOP_REQUEST              = 1,
	GKR_ASK_CONTINUE_REQUEST          = 2
} GkrAskCheckAction;

#define GKR_ASK_REQUEST_OK_DENY_BUTTONS \
	(GKR_ASK_REQUEST_OK_BUTTON | GKR_ASK_REQUEST_DENY_BUTTON)
#define GKR_ASK_REQUEST_NEW_PASSWORD  \
	(GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_CONFIRM_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS) 
#define GKR_ASK_REQUEST_PROMPT_PASSWORD \
	(GKR_ASK_REQUEST_PASSWORD | GKR_ASK_REQUEST_OK_DENY_BUTTONS)
#define GKR_ASK_REQUEST_ACCESS_SOMETHING \
	(GKR_ASK_REQUEST_ALLOW_BUTTON | GKR_ASK_REQUEST_ALLOW_FOREVER_BUTTON | GKR_ASK_REQUEST_DENY_BUTTON)

#define GKR_TYPE_ASK_REQUEST             (gkr_ask_request_get_type ())
#define GKR_ASK_REQUEST(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_ASK_REQUEST, GkrAskRequest))
#define GKR_ASK_REQUEST_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_ASK_REQUEST, GObject))
#define GKR_IS_ASK_REQUEST(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_ASK_REQUEST))
#define GKR_IS_ASK_REQUEST_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_ASK_REQUEST))
#define GKR_ASK_REQUEST_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_ASK_REQUEST, GkrAskRequestClass))

typedef struct _GkrAskRequest      GkrAskRequest;
typedef struct _GkrAskRequestClass GkrAskRequestClass;

struct _GkrAskRequest {
	GObject parent;

	/* Results */
	GkrAskResponse response;
	gchar* original_password;
	gchar* typed_password;
};

struct _GkrAskRequestClass {
	GObjectClass parent_class;
	
	/* A callback called before and after request to check if still valid */
	GkrAskCheckAction (*check_request) (GkrAskRequest *ask);
	
	void (*completed) (GkrAskRequest *ask);
};

GType              gkr_ask_request_get_type         (void)G_GNUC_CONST;

GkrAskRequest*     gkr_ask_request_new              (const gchar *title,
                                                     const gchar *primary,
                                                     guint flags);

void               gkr_ask_request_set_secondary    (GkrAskRequest *ask, 
                                                     const gchar *secondary);

GObject*           gkr_ask_request_get_object       (GkrAskRequest *ask);

void               gkr_ask_request_set_object       (GkrAskRequest *ask,
                                                     GObject *object);

gboolean           gkr_ask_request_check            (GkrAskRequest *ask);

void               gkr_ask_request_prompt           (GkrAskRequest *ask);

void               gkr_ask_request_cancel           (GkrAskRequest *ask);

gboolean           gkr_ask_request_is_complete      (GkrAskRequest *ask);

G_END_DECLS

#endif /* __GKR_ASK_REQUEST_H__ */

