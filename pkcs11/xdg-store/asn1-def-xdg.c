#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const ASN1_ARRAY_TYPE xdg_asn1_tab[] = {
  { "XDG", 536872976, NULL },
  { NULL, 1073741836, NULL },
  { "TrustDigest", 1610612741, NULL },
  { "algorithm", 1073741836, NULL },
  { "digest", 7, NULL },
  { "TrustDigests", 1610612747, NULL },
  { NULL, 2, "TrustDigest"},
  { "TrustLevel", 1610874901, NULL },
  { "trustUnknown", 1073741825, "0"},
  { "untrustedUsage", 1073741825, "1"},
  { "mustVerify", 1073741825, "2"},
  { "trustedUsage", 1073741825, "3"},
  { "trustedDelegator", 1, "4"},
  { "TrustPair", 1610612741, NULL },
  { "purpose", 1073741836, NULL },
  { "level", 2, "TrustLevel"},
  { "TrustPairs", 1610612747, NULL },
  { NULL, 2, "TrustPair"},
  { "CertReference", 1610612741, NULL },
  { "serialNumber", 1073741827, NULL },
  { "issuer", 1073741837, NULL },
  { "subject", 1073758221, NULL },
  { "digests", 2, "TrustDigests"},
  { "TrustReference", 1610612754, NULL },
  { "certReference", 2, "CertReference"},
  { "trust-1", 536870917, NULL },
  { "reference", 1073741826, "TrustReference"},
  { "trusts", 2, "TrustPairs"},
  { NULL, 0, NULL }
};
