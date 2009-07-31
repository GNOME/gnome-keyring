
NULL =

BUILT_SOURCES = \
	secrets-built-sources.stamp

# Note: Also copied again in rule below	
INTERFACE_DEFS = \
	org.freedesktop.Secrets.xml \
	$(NULL)	
	
secrets-built-sources.stamp : Makefile.am $(INTERFACE_DEFS)
	eggdbus-binding-tool							\
		--namespace "Secrets"						\
		--dbus-namespace "org.freedesktop.Secrets"			\
		--introspection-xml $(srcdir)/org.freedesktop.Secrets.xml	\
		--stamp-file $@							\
	$(NULL)

EXTRA_DIST = \
	$(INTERFACE_DEFS)
	
