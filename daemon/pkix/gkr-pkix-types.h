#ifndef GKRPKIXTYPES_H_
#define GKRPKIXTYPES_H_

typedef enum _GkrPkixResult {
	GKR_PKIX_FAILURE = -2,
	GKR_PKIX_CANCELLED = -1,
	GKR_PKIX_UNRECOGNIZED = 0,
	GKR_PKIX_SUCCESS = 1
} GkrPkixResult;

/* 
 * There are switch statements that use these in various 
 * places in the code. When adding a type, make sure
 * to search them out and add cases for the new type.
 */
#define  GKR_PKIX_CERTIFICATE      (g_quark_from_static_string ("certificate"))
#define  GKR_PKIX_PUBLIC_KEY       (g_quark_from_static_string ("public-key"))
#define  GKR_PKIX_PRIVATE_KEY      (g_quark_from_static_string ("private-key"))

#endif /*GKRPKIXTYPES_H_*/
