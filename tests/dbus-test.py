#!/usr/bin/python

import dbus

bus = dbus.SessionBus()

proxy_obj = bus.get_object('org.gnome.keyring', '/org/gnome/keyring/daemon')
service = dbus.Interface(proxy_obj, 'org.gnome.keyring.Daemon')

print "Socket Path: "
print service.GetSocketPath()

print "\nEnvironment: "
env = service.GetEnvironment()
for (name, value) in env.items():
	print "%s=%s" % (name, value)
