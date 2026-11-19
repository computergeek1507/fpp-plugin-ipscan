#!/bin/bash
if [ -L /usr/local/bin/ipscan ]; then
    rm -f /usr/local/bin/ipscan 2>/dev/null || sudo rm -f /usr/local/bin/ipscan || true
fi
MEDIA=${MEDIADIR:-/home/fpp/media}
rm -rf "$MEDIA/plugindata/fpp-plugin-ipscan"
