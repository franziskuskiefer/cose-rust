#!/bin/bash

cwd=$(cd $(dirname $0); pwd -P)
MOZILLA_CENTRAL=${MOZILLA_CENTRAL:-"$cwd/../../../mc"}
script_path="$MOZILLA_CENTRAL/security/manager/ssl/tests/unit"

python_path="$MOZILLA_CENTRAL/python/pyasn1/"
python_path="$python_path:$MOZILLA_CENTRAL/python/pyasn1-modules/"
python_path="$python_path:$MOZILLA_CENTRAL/python/PyECC/"
python_path="$python_path:$MOZILLA_CENTRAL/python/mock-1.0.0/"
python_path="$python_path:$MOZILLA_CENTRAL/python/rsa/"

gen_cert() {
    PYTHONPATH=$python_path "$script_path"/pycert.py "$@" > /tmp/cert.pem
    openssl x509 -in /tmp/cert.pem -out /tmp/cert.der -outform DER
    xxd -ps /tmp/cert.der | gsed 's/\([0-9A-Fa-f]\{2\}\)/0x\1, /g' \
                          | tr -d '\n'
    echo ""
}

gen_cert "${@:1}"
