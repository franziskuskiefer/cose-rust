#!/bin/bash

cwd=$(cd $(dirname $0); pwd -P)
MOZILLA_CENTRAL=${MOZILLA_CENTRAL:-"$cwd/../../../mc"}
script_path="$MOZILLA_CENTRAL/security/manager/ssl/tests/unit"

python_path="$MOZILLA_CENTRAL/python/pyasn1/"
python_path="$python_path:$MOZILLA_CENTRAL/python/pyasn1-modules/"
python_path="$python_path:$MOZILLA_CENTRAL/python/PyECC/"
python_path="$python_path:$MOZILLA_CENTRAL/python/mock-1.0.0/"
python_path="$python_path:$MOZILLA_CENTRAL/python/rsa/"

case $1 in
	-c) PYTHONPATH=$python_path "$script_path"/pycert.py "${@:2}" ;;
	-k) PYTHONPATH=$python_path "$cwd"/pykey.py "${@:2}" ;;
	*) echo "Use certs.sh -c (cert) or -k (key)"; exit 2 ;;
esac
