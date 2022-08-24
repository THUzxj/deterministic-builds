#!/bin/bash

if [[ `whoami` != "root" ]]; then
    echo "Should run in root"
    exit 1
fi

set -x

BPF_Apps=('modify_time' 'modify_file_timestamp' 'modify_file_read' 'preload_filter')

for app in "${BPF_Apps[@]}"; do
    echo "Killing $app"
    processes=$(ps aux | grep ${app} | awk '{print $2}')
    if [[ -z $processes ]]; then
        echo "Process about $app is empty"
        exit 1
    fi
    for pid in $processes; do
        echo "killing process $pid"
        kill -2 $pid
    done
done

cd ${PRELOAD_DIR_PATH}
./unload_modify.sh
cd ..

set +x
