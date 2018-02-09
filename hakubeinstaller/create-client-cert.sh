#!/bin/bash

set -e

#
# A script that generates a client certificate signed by a given CA.
#
# NOTE: relies on cfssl and cfssljson being installed.
#

scriptname=$(basename ${0})

# default output_dir
output_dir=$(realpath assets/pki)

function die_with_error() {
    echo "[${scriptname}] error: $1" 2>&1
    echo
    echo "Generates a client key and certificate signed by a given CA."
    echo
    echo "usage: ${scriptname} [OPTIONS] CN"
    echo "  --output-dir=PATH     Directory where cert and key will be written."
    echo "                        Default: ${output_dir}"
    echo "  --ca-cert=PATH        The CA cert to sign with."
    echo "                        Default: \${output_dir}/ca.pem"
    echo "  --ca-key=PATH         The CA key to sign with."
    echo "                        Default: \${output_dir}/ca-key.pem"
    echo "  --ca-config=PATH      The CA configuration to use."
    echo "                        Default: \${output_dir}/ca-config.json"    
    exit 1
}

for arg in $@; do
    case ${arg} in
	--output-dir=*)
	    output_dir=${arg#--output-dir=}
	    ;;
	--ca-cert=*)
	    ca_cert=${arg#--ca-cert=}
	    ;;
	--ca-key=*)
	    ca_key=${arg#--ca-key=}
	    ;;
	--ca-config=*)
	    ca_config=${arg#--ca-config=}
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

[ "${1}" = "" ] && die_with_error "no client common name (CN) given"
client_common_name=${1}
ca_cert=${ca_cert:-${output_dir}/ca.pem}
ca_key=${ca_key:-${output_dir}/ca-key.pem}
ca_config=${ca_config:-${output_dir}/ca-config.json}
client_config=${output_dir}/${client_common_name}.json

mkdir -p ${output_dir}


cat > ${client_config} <<EOL
{
    "CN": "${client_common_name}",
    "key": {
        "algo": "ecdsa",
        "size": 256
    }
}
EOL

# generate client cert
cd ${output_dir}
cfssl gencert -ca=${ca_cert} -ca-key=${ca_key} -config=${ca_config} -profile=client ${client_config} | cfssljson -bare ${client_common_name}

# clean up
rm *csr ${client_config}
