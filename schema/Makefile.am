
gsettings_SCHEMAS = \
	schema/org.gnome.crypto.cache.gschema.xml

@GSETTINGS_RULES@

convertdir = $(datarootdir)/GConf/gsettings
convert_DATA = \
	schema/org.gnome.crypto.cache.convert

noinst_DATA += gschemas.compiled

gschemas.compiled: $(gsettings_SCHEMAS)
	$(AM_V_GEN) glib-compile-schemas --strict .

CLEANFILES += \
	gschemas.compiled

EXTRA_DIST += \
	$(convert_DATA) \
	$(gsettings_SCHEMAS)