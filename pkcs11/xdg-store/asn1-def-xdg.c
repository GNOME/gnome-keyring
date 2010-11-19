#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const ASN1_ARRAY_TYPE xdg_asn1_tab[] = {
  { "XDG", 536872976, NULL },
  { NULL, 1073741836, NULL },
  { "TrustLevel", 1610874901, NULL },
  { "unknown", 1073741825, "0"},
  { "untrusted", 1073741825, "1"},
  { "trusted", 1073741825, "3"},
  { "trustedAnchor", 1, "4"},
  { "TrustAssertion", 1610612741, NULL },
  { "purpose", 1073741836, NULL },
  { "level", 1073741826, "TrustLevel"},
  { "with", 1073741831, NULL },
  { "additions", 536870923, NULL },
  { NULL, 13, NULL },
  { "TrustAssertions", 1610612747, NULL },
  { NULL, 2, "TrustAssertion"},
  { "CertReference", 1610612741, NULL },
  { "serialNumber", 1073741827, NULL },
  { "issuer", 1073741837, NULL },
  { "subject", 1073758221, NULL },
  { "additions", 536870923, NULL },
  { NULL, 13, NULL },
  { "TrustReference", 1610612754, NULL },
  { "certReference", 1610620930, "CertReference"},
  { NULL, 2056, "0"},
  { "certComplete", 1610620941, NULL },
  { NULL, 2056, "1"},
  { "additions", 536879117, NULL },
  { NULL, 2056, "2"},
  { "trust-1", 536870917, NULL },
  { "reference", 1073741826, "TrustReference"},
  { "assertions", 1073741826, "TrustAssertions"},
  { "additions", 536870923, NULL },
  { NULL, 13, NULL },
  { NULL, 0, NULL }
};
