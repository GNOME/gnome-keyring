if get_option('manpage')
  install_man('gnome-keyring-3.1')

  xml_manfiles = [
    'gnome-keyring-daemon.xml',
    'gnome-keyring.xml',
  ]

  xsltproc = find_program('xsltproc')
  foreach xml_man : xml_manfiles
    custom_target('manpage-@0@'.format(xml_man),
      input: xml_man,
      output: '@BASENAME@.1',
      install: true,
      install_dir: get_option('mandir') / 'man1',
      command: [
        xsltproc,
        '--nonet',
        '--stringparam', 'man.output.quietly', '1',
        '--stringparam', 'funcsynopsis.style', 'ansi',
        '--stringparam', 'man.th.extra1.suppress', '1',
        '--stringparam', 'man.authors.section.enabled', '0',
        '--stringparam', 'man.copyright.section.enabled', '0',
        '-o', '@OUTPUT@',
        'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
        '@INPUT@'
      ]
    )
  endforeach
endif
