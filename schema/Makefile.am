
gsettings_SCHEMAS = \
	org.gnome.crypto.cache.gschema.xml

@GSETTINGS_RULES@

convert_DATA = \
	org.gnome.crypto.cache.convert

convertdir = \
	$(datarootdir)/GConf/gsettings

all-local: gschemas.compiled

gschemas.compiled: $(gsettings_SCHEMAS)
	glib-compile-schemas --strict .

DISTCLEAN = \
	gschemas.compiled

EXTRA_DIST = \
	$(convert_DATA) \
	$(gsettings_SCHEMAS)