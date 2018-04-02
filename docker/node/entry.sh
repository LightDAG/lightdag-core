#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

network="$(cat /etc/lightdag-network)"
case "${network}" in
        live|'')
                network='live'
                dirSuffix=''
                ;;
        beta)
                dirSuffix='Beta'
                ;;
        test)
                dirSuffix='Test'
                ;;
esac

lightdag_dir="${HOME}/LightDAG${dirSuffix}"
mkdir -p "${lightdag_dir}"
if [ ! -f "${lightdag_dir}/config.json" ]; then
        echo "Config File not found, adding default."
        cp "/usr/share/lightdag/config/${network}.json" "${lightdag_dir}/config.json"
fi

/usr/bin/lightdag_node --daemon
