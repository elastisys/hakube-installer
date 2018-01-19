#!/bin/bash

set -e

# set a default locale
sudo locale-gen "en_US.UTF-8"
sudo tee -a /etc/environment  <<EOF
LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
EOF

sudo apt-get update -y
sudo apt-get install -qy haproxy


sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOF
global
  log /dev/log    local0
  log /dev/log    local1 notice
  chroot /var/lib/haproxy
  stats socket /run/haproxy/admin.sock mode 660 level admin
  stats timeout 30s
  user haproxy
  group haproxy
  daemon

  # Default SSL material locations
  ca-base /etc/ssl/certs
  crt-base /etc/ssl/private
  # Default ciphers to use on SSL-enabled listening sockets.
  # For more information, see ciphers(1SSL). This list is from:
  #  https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
  ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS
  ssl-default-bind-options no-sslv3

defaults
  log global
  timeout connect 5000
  timeout client  60000
  timeout server  60000

# show stats on :6444
frontend stats
  mode   http
  bind   0.0.0.0:6444
  mode   http
  option httplog
  option dontlognull
  stats  enable
  stats  refresh 2s
  stats  uri /

frontend frontend
   mode tcp
   option tcplog
   bind 0.0.0.0:6443
   default_backend backends

backend backends
 mode tcp
 balance roundrobin
 option tcplog
 option tcp-check
 #option log-health-checks
 # health checks every 2s, 2 fails => DOWN, 3 success => UP
 default-server inter 2s fall 2 rise 3
 server master0-api 10.2.0.10:6443 check on-marked-down shutdown-sessions
 server master1-api 10.2.0.11:6443 check on-marked-down shutdown-sessions
 server master2-api 10.2.0.12:6443 check on-marked-down shutdown-sessions
EOF

sudo systemctl enable haproxy
sudo systemctl restart haproxy

# to make rsyslog start accepting logs to /var/log/haproxy.log
sudo systemctl restart rsyslog
