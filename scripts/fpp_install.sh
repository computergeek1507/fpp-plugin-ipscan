#!/bin/bash
# Nothing to build: the scanner is plain Python 3 (standard library only).
BASEDIR=$(cd "$(dirname "$0")/.." && pwd)
chmod +x "$BASEDIR/scripts/ipscan.py"

# Make the command line tool available as "ipscan" when we can.
if [ -w /usr/local/bin ] || [ "$(id -u)" = "0" ]; then
    ln -sf "$BASEDIR/scripts/ipscan.py" /usr/local/bin/ipscan
elif command -v sudo >/dev/null 2>&1; then
    sudo ln -sf "$BASEDIR/scripts/ipscan.py" /usr/local/bin/ipscan || true
fi

MEDIA=${MEDIADIR:-/home/fpp/media}
mkdir -p "$MEDIA/plugindata/fpp-plugin-ipscan"
chown -R fpp:fpp "$MEDIA/plugindata/fpp-plugin-ipscan" 2>/dev/null || true
