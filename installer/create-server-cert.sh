#!/bin/bash

set -e

#
# A script that generates a server and peer certificate signed by a given CA.
#
# NOTE: relies on cfssl and cfssljson being installed.
#

scriptname=$(basename ${0})

# default output_dir
output_dir=$(realpath assets/pki)

function die_with_error() {
    echo "[${scriptname}] error: $1" 2>&1
    echo
    echo "Generates a server and peer key and certificate signed by a given CA."
    echo
    echo "usage: ${scriptname} [OPTIONS] CN HOST ..."
    echo "  --output-dir=PATH   Directory where certs and keys will be written."
    echo "                      Default: ${output_dir}"
    echo "  --ca-cert=PATH      The CA cert to sign with."
    echo "                      Default: \${output_dir}/ca.pem"
    echo "  --ca-key=PATH       The CA key to sign with."
    echo "                      Default: \${output_dir}/ca-key.pem"
    echo "  --ca-config=PATH    The CA configuration to use."
    echo "                      Default: \${output_dir}/ca-config.json"    
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

[ "${1}" = "" ] && die_with_error "no server/peer common name (CN) given"
[ "${2}" = "" ] && die_with_error "at least one server IP/hostname is required"
hostnames="\"${2}\""
for host in ${@:3}; do
    hostnames="${hostnames}, \"${host}\""
done

server_common_name=${1}
ca_cert=${ca_cert:-${output_dir}/ca.pem}
ca_key=${ca_key:-${output_dir}/ca-key.pem}
ca_config=${ca_config:-${output_dir}/ca-config.json}
server_config=${output_dir}/${server_common_name}.json

mkdir -p ${output_dir}

# generate server and peer cert
cat > ${server_config} <<EOF
{
    "CN": "${server_common_name}",
    "hosts": [ ${hostnames} ],
    "key": { "algo": "ecdsa", "size": 256 },
    "names": [ { "C": "US" } ]
}
EOF

# generate client cert
cd ${output_dir}
cfssl gencert -ca=${ca_cert} -ca-key=${ca_key} -config=${ca_config} -profile=server ${server_config} | cfssljson -bare ${server_common_name}-server
cfssl gencert -ca=${ca_cert} -ca-key=${ca_key} -config=${ca_config} -profile=server ${server_config} | cfssljson -bare ${server_common_name}-peer

# clean up
rm *csr ${server_config}
