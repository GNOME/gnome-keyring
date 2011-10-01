
SPEC = org.gnome.keyring.Prompter.xml

EXTRA_DIST = \
	$(SPEC) \
	docbook-params.xml

CLEANFILES = \
	prompter.xml \
	html/*.html

if ENABLE_GTK_DOC

all-local: prompter.xml html/index.html

html/index.html: prompter.xml docbook-params.xsl $(SPEC)
	xmlto --skip-validation -o html/ -x docbook-params.xsl xhtml prompter.xml

prompter.xml: $(top_srcdir)/docs/tools/spec-to-docbook.xsl $(SPEC)
	xsltproc $(top_srcdir)/docs/tools/spec-to-docbook.xsl $(SPEC) > $@

endif
