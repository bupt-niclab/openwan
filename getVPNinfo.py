#!/usr/bin/env python

from ncclient import manager

def connect(host, port, user, password):
  conn = manager.connect(host=host, port=port, username=user, password=password, timeout=10, device_params = {'name':'junos'},
  hostkey_verify=False)

  print 'show security ike security-associations'
  print '*' * 30
  result = conn.command(command='show security ike security-associations', format='xml')
  print result.tostring

  print 'show security ipsec security-associations'
  print '*' * 30
  result = conn.command('show security ipsec security-associations', format='xml')
  print result.tostring

if __name__ == '__main__':
  connect('192.168.0.13', '22', 'root', 'r00t10086!')
