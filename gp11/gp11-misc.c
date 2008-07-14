
#include "gp11.h"

#include <glib/gi18n.h>

GQuark
gp11_get_error_quark (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gp11-error");
	return domain;
}

void
gp11_list_unref_free (GList *reflist)
{
	GList *l;
	for (l = reflist; l; l = g_list_next (l)) {
		g_return_if_fail (G_IS_OBJECT (l->data));
		g_object_unref (l->data);
	}
	g_list_free (reflist);
}

const gchar*
gp11_message_from_rv (CK_RV rv)
{
	switch (rv) {
	
	/* These are not really errors, or not current */
	case CKR_OK:
	case CKR_NO_EVENT:
	case CKR_FUNCTION_NOT_PARALLEL:
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		g_return_val_if_reached ("");
		
	case CKR_CANCEL:
	case CKR_FUNCTION_CANCELED:
		return _("The operation was cancelled");
		
	case CKR_HOST_MEMORY:
		return _("Insufficient memory available");
	case CKR_SLOT_ID_INVALID:
		return _("The specified slot ID is not valid");
	case CKR_GENERAL_ERROR:
		return _("Internal error");
	case CKR_FUNCTION_FAILED:
		return _("The operation failed");
	case CKR_ARGUMENTS_BAD:
		return _("Invalid arguments");
	case CKR_NEED_TO_CREATE_THREADS:
		return _("The module cannot created needed threads");
	case CKR_CANT_LOCK:
		return _("The module cannot lock data properly");
	case CKR_ATTRIBUTE_READ_ONLY:
		return _("The field is read-only");
	case CKR_ATTRIBUTE_SENSITIVE:
		return _("The field is sensitive and cannot be revealed");
	case CKR_ATTRIBUTE_TYPE_INVALID:
		return _("The field is invalid or does not exist");
	case CKR_ATTRIBUTE_VALUE_INVALID:
		return _("Invalid value for field");
	case CKR_DATA_INVALID:
		return _("The data is not valid or unrecognized");
	case CKR_DATA_LEN_RANGE:
		return _("The data is too long");
	case CKR_DEVICE_ERROR:
		return _("An error occurred on the device");
	case CKR_DEVICE_MEMORY:
		return _("Insufficient memory available on device");
	case CKR_DEVICE_REMOVED:
		return _("The device was removed or unplugged");
	case CKR_ENCRYPTED_DATA_INVALID:
		return _("The encrypted data is not valid or unrecognized");
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		return _("The encrypted data is too long");
	case CKR_FUNCTION_NOT_SUPPORTED:
		return _("This operation is not supported");
	case CKR_KEY_HANDLE_INVALID:
		return _("The key is missing or invalid");
	case CKR_KEY_SIZE_RANGE:
		return _("The key is the wrong size");
	case CKR_KEY_TYPE_INCONSISTENT:
		return _("The key is of the wrong type");
	case CKR_KEY_NOT_NEEDED:
		return _("No key is needed");
	case CKR_KEY_CHANGED:
		return _("The key is different than before");
	case CKR_KEY_NEEDED:
		return _("A key is needed");
	case CKR_KEY_INDIGESTIBLE:
		return _("Cannot include the key in digest");
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		return _("This operation cannot be done with this key");
	case CKR_KEY_NOT_WRAPPABLE:
		return _("The key cannot be wrapped");
	case CKR_KEY_UNEXTRACTABLE:
		return _("Cannot export this key");
	case CKR_MECHANISM_INVALID:
		return _("The crypto mechanism is invalid or unrecognized");
	case CKR_MECHANISM_PARAM_INVALID:
		return _("The crypto mechanism has an invalid argument");
	case CKR_OBJECT_HANDLE_INVALID:
		return _("The object is missing or invalid");
	case CKR_OPERATION_ACTIVE:
		return _("Another operation is already taking place");
	case CKR_OPERATION_NOT_INITIALIZED:
		return _("No operation is taking place");
	case CKR_PIN_INCORRECT:
		return _("The password or PIN is incorrect");
	case CKR_PIN_INVALID:
		return _("The password or PIN is invalid");
	case CKR_PIN_LEN_RANGE:
		return _("The password or PIN is of an invalid length");
	case CKR_PIN_EXPIRED:
		return _("The password or PIN has expired");
	case CKR_PIN_LOCKED:
		return _("The password or PIN is locked");
	case CKR_SESSION_CLOSED:
		return _("The session is closed");
	case CKR_SESSION_COUNT:
		return _("Too many sessions are active");
	case CKR_SESSION_HANDLE_INVALID:
		return _("The session is invalid");
	case CKR_SESSION_READ_ONLY:
		return _("The session is read-only");
	case CKR_SESSION_EXISTS:
		return _("An open session exists");
	case CKR_SESSION_READ_ONLY_EXISTS:
		return _("A read-only session exists");
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return _("An administrator session exists");
	case CKR_SIGNATURE_INVALID:
		return _("The signature is bad or corrupted");
	case CKR_SIGNATURE_LEN_RANGE:
		return _("The signature is unrecognized or corrupted");
	case CKR_TEMPLATE_INCOMPLETE:
		return _("Certain required fields are missing");
	case CKR_TEMPLATE_INCONSISTENT:
		return _("Certain fields have invalid values");
	case CKR_TOKEN_NOT_PRESENT:
		return _("The device is not present or unplugged");
	case CKR_TOKEN_NOT_RECOGNIZED:
		return _("The device is invalid or unregocnizable");
	case CKR_TOKEN_WRITE_PROTECTED:
		return _("The device is write protected");
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		return _("Cannot import because the key is invalid");
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		return _("Cannot import because the key is of the wrong size");
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		return _("Cannot import because the key is of the wrong type");
	case CKR_USER_ALREADY_LOGGED_IN:
		return _("You are already logged in");
	case CKR_USER_NOT_LOGGED_IN:
		return _("No user has logged in");
	case CKR_USER_PIN_NOT_INITIALIZED:
		return _("The user's password or PIN is not set");
	case CKR_USER_TYPE_INVALID:
		return _("The user is of an invalid type");
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		return _("Another user is already logged in");
	case CKR_USER_TOO_MANY_TYPES:
		return _("Too many users of different types logged in");
	case CKR_WRAPPED_KEY_INVALID:
		return _("Cannot import an invalid key");
	case CKR_WRAPPED_KEY_LEN_RANGE:
		return _("Cannot import a key of the wrong size");
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		return _("Cannot export because the key is invalid");
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		return _("Cannot export because the key is of the wrong size");
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		return _("Cannot export because the key is of the wrong type");
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		return _("Cannot set a random seed");
	case CKR_RANDOM_NO_RNG:
		return _("No random number generator available");
	case CKR_DOMAIN_PARAMS_INVALID:
		return _("The crypto mechanism has an invalid parameter");
	case CKR_BUFFER_TOO_SMALL:
		return _("Not enough space to store the result");
	case CKR_SAVED_STATE_INVALID:
		return _("The saved state is invalid");
	case CKR_INFORMATION_SENSITIVE:
		return _("The information is sensitive and cannot be revealed");
	case CKR_STATE_UNSAVEABLE:
		return _("The state cannot be saved");
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		return _("The module has not been initialized");
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return _("The module has already been initialized");
	case CKR_MUTEX_BAD:
		return _("Cannot lock data");
	case CKR_MUTEX_NOT_LOCKED:
		return _("The data cannot be locked");
	case CKR_FUNCTION_REJECTED:
		return _("The signature request was rejected by the user");
		
	default:
		g_message ("unknown error: %u", (guint)rv);
		return _("Unknown error");
	}
}

gchar*
gp11_string_from_chars (const guchar *data, gsize max)
{
	gchar *string;
	
	g_return_val_if_fail (data, NULL);
	g_return_val_if_fail (max, NULL);
	
	string = g_strndup ((gchar*)data, max);
	g_strstrip (string);
	return string;
}
