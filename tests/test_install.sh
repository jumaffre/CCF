#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

function service_http_status()
{
    echo $(curl -o /dev/null -s https://127.0.0.1:8000/app/commit -w "%{http_code}" --key ./workspace/sandbox_common/user0_privk.pem --cert ./workspace/sandbox_common/user0_cert.pem --cacert ./workspace/sandbox_common/networkcert.pem)
}

if [ "$#" -ne 1 ]; then
    echo "Install prefix should be passed as first argument to $0"
    exit 1
fi

echo "Install prefix is ${1}"

# Setup env
INSTALL_PREFIX="$1"
working_dir="nested/run"
rm -rf "$working_dir"
mkdir -p "$working_dir"
cd "$working_dir"

# Start ephemeral network in the background
network_live_time=60
timeout --signal=SIGINT --kill-after=${network_live_time}s --preserve-status ${network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh --verbose &

# Poll until service is open
while [ ! $(service_http_status) == "200" ]; do
    echo "Waiting for service to open..."
    sleep 1
done

# # Issue tutorial transactions to ephemeral network
python3.8 -m venv env
source env/bin/activate
python -m pip install ../../../python
python ../../../python/tutorial.py ./workspace/sandbox_0/0.ledger/ ./workspace/sandbox_common/

# Test Python package CLI
../../../tests//test_python_cli.sh > test_python_cli.out

# Poll until service has died
while [ $(service_http_status) == "200" ]; do
    echo "Waiting for service to close..."
    sleep 1
done

# Recover network
cp -r ./workspace/sandbox_0/0.ledger .

recovered_network_live_time=30
timeout --signal=SIGINT --kill-after=${recovered_network_live_time}s --preserve-status ${recovered_network_live_time}s \
"$INSTALL_PREFIX"/bin/sandbox.sh --verbose \
    --recover \
    --ledger-dir 0.ledger \
    --common-dir ./workspace/sandbox_common/