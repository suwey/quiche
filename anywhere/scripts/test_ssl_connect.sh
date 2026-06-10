#!/bin/bash
SERVER=1.1.1.1
SNI=www.qq.com

openssl s_client -connect $SERVER \
     -servername $SNI -alpn h2 2>&1 |
     grep -q "CONNECTED" && echo OK || echo FAIL