
man1_MANS = \
	gnome-keyring-daemon.1
	$(NULL)

MAN_IN_FILES = \
	$(man1_MANS:.1=.xml)

CLEANFILES = \
	$(man1_MANS)

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

EXTRA_DIST = \
	file-format.txt \
	keyring-intro.txt \
	gnome-keyring.svg \
	$(MAN_IN_FILES)
