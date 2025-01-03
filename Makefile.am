## Makefile.am -- Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = foreign dist-bzip2 no-dist-gzip subdir-objects
bin_PROGRAMS = banhammer banhammerd
dist_bin_SCRIPTS = banstat
banhammer_SOURCES = src/banhammer.c src/banlib.c
banhammerd_SOURCES = src/banhammerd.c src/banlib.c
banhammer_CFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\"
mandir = $(prefix)/man
dist_man_MANS = doc/banhammer.8
dist_sysconf_DATA = etc/banhammer.conf.sample
docdir = $(datadir)/doc/@PACKAGE@
dist_doc_DATA = doc/README doc/COPYING doc/FAQ
rcdir = $(sysconfdir)/rc.d
dist_rc_SCRIPTS = etc/banhammerd
periodicdir = $(sysconfdir)/periodic/security
dist_periodic_SCRIPTS = etc/800.banstat
