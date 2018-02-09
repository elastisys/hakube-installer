#!/bin/bash

set -e

#
# A script that generates a CA certificate.
#
# NOTE: relies on cfssl and cfssljson being installed.
#

scriptname=$(basename ${0})

# default output_dir
output_dir=$(realpath assets/pki)
# default expiry: 20 years
expiry="175200h"

function die_with_error() {
    echo "[${scriptname}] error: $1" 2>&1
    echo
    echo "Generates a CA key and certificate."
    echo
    echo "usage: ${scriptname} [OPTIONS] CN"
    echo "  --output-dir=PATH     Directory where CA cert will be written."
    echo "                        Default: ${output_dir}"
    echo "  --expiry=DURATION     When the created CA certificate is to expire."
    echo "                        Default: ${expiry}"
    exit 1
}

for arg in $@; do
    case ${arg} in
	--output-dir=*)
	    output_dir=${arg#--output-dir=}
	    ;;
	--expiry=*)
	    expiry=${arg#--expiry=}
	    ;;
	--help)
	    die_with_error ""
	    ;;
	--*)
	    die_with_error "unrecognized option: ${arg}"
	    ;;
	*)
	    # assume only positional arguments left
	    break;
    esac
    shift
done

[ "${1}" = "" ] && die_with_error "no CA common name (CN) given"
ca_common_name=${1}


mkdir -p ${output_dir}

cat > ${output_dir}/ca-config.json <<EOF
 {
     "signing": {
         "default": {
             "expiry": "${expiry}"
         },
         "profiles": {
             "server": {
                 "expiry": "${expiry}",
                 "usages": [
                     "signing",
                     "key encipherment",
                     "server auth",
                     "client auth"
                 ]
             },
             "client": {
                 "expiry": "${expiry}",
                 "usages": [
                     "signing",
                     "key encipherment",
                     "client auth"
                 ]
             },
             "peer": {
                 "expiry": "${expiry}",
                 "usages": [
                     "signing",
                     "key encipherment",
                     "server auth",
                     "client auth"
                 ]
             }
         }
     }
 }
EOF

cat > ${output_dir}/ca-csr.json <<EOL
 {
     "CN": "${ca_common_name}",
     "key": {
         "algo": "rsa",
         "size": 2048
     }
 }
EOL


cd ${output_dir}
# generate CA cert
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -

# clean up
rm *csr
