
generated_mans = \
	gnome-keyring-daemon.1 \
	gnome-keyring.1 \
	$(NULL)

man1_MANS = $(generated_mans) \
	docs/gnome-keyring-3.1 \
	$(NULL)

MAN_IN_FILES = \
	docs/gnome-keyring-daemon.xml \
	docs/gnome-keyring.xml

CLEANFILES += \
	$(generated_mans)

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

XSLTPROC_MAN = \
	$(XSLTPROC) $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

.xml.1:
	$(AM_V_GEN) $(XSLTPROC_MAN) $<

EXTRA_DIST += \
	docs/file-format.txt \
	docs/keyring-intro.txt \
	docs/gnome-keyring.svg \
	$(generated_mans) \
	$(MAN_IN_FILES) \
	docs/gnome-keyring-3.1 \
	$(NULL)
