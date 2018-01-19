# Kubernetes HA cluster installer
This repository contains a
[kubeadm](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/)-based
installer for a highly available Kubernetes cluster with a configurable number
of master and worker nodes.

The installer should run on any Linux system which meets the software
prerequisites outlined below.

Just like `kubeadm`, this installer should work with both bare-metal and cloud
servers. To make use of cloudprovider-specific features, like volumes or
load-balancers, some cloudprovider config may be needed. Hooks are provided to
pass small configuration fragments for such purposes.

The installer script assumes that Ubuntu (16.04) servers on which to install
Kubernetes have a already been provisioned. *Infrastructure providers* are used
to create cloud infrastructure (such as servers). Some examples are available
under [infra-providers](infra-providers). At the moment, two infrastructure
providers are implemented:

  - an [AWS infra-provider](infra-providers/aws), which creates a cloud
    infrastructure via [Terraform](https://www.terraform.io/).
  - a [Vagrant infra-provider](infra-providers/vagrant), which uses Vagrant
    to start cluster VMs locally on a single host.

The general workflow is to

0. Use an [infra-provider](infra-providers) (or any other means) to provision
   cluster machines for the Kubernetes masters and workers. Note that at least 3
   masters are required for a HA setup to work. A smaller number
   prevents [etcd](https://coreos.com/etcd/) from forming a quorum. A
   load-balancer also needs to be provisioned to distribute HTTPS traffic over
   the masters on port `6443` (the `kube-apiserver` port).
0. Declare a *cluster definition* (in JSON) for the cluster installer. The
   format is described below.
0. Use the installer to render *cluster assets*. The cluster assets consists of
   secrets (cluster token, certificates, ssh keys) and boot scripts for each
   master and worker.
0. After inspecting the boot scripts, use the installer to install the cluster
   by running the boot scripts (over SSH) against the master and workers
   declared in the cluster definition.


## Cluster definition
A cluster definition describes the nodes that constitute the cluster and may
optionally contain hooks to configure the cluster for a particular
cloudprovider.

An example cluster definition for an AWS cluster may look as follows:

**NOTE: the bracket-prefixed comments are provided for clarity, they are NOT
permitted by the json parser.**

```
{
    # (Optional) A DNS name intended to be given to the master
    # load-balancer, which may be used to access the Kubernetes API server.
    # It will be added as a subject alternate name to the generated master
    # certificates.
    "masterFQDN": "mykubeapi.elastisys.com",
    # The IP address where the master load-balancer can be reached.
    # Note: this option is mutually exclusive with masterLoadBalancerFQDN.
    "masterLoadBalancerIP": null,
    # The DNS name where the master load-balancer can be reached (in some
    # cases, such as AWS ELB, the load-balancer is not assigned a single
    # static IP address and in such cases a FQDN needs to be used).
    # Note: this option is mutually exclusive with masterLoadBalancerFQDN.
    "masterLoadBalancerFQDN": "mykube-master-lb-4c88cd5b9c8c3223.elb.us-east-1.amazonaws.com",
    # (Optional) The username to use when logging in over SSH. Typically
    # 'ubuntu'.
    "sshLoginUser": "ubuntu",
    # (Optional) A private SSH login key to use when connecting to nodes.
    # Can be override on a per-node basis (see below).
    "sshLoginKey": "~/.ssh/id_rsa",
    # The list of master nodes in the cluster. A minimum of 3 masters is
    # required.
    "masters": [
        {
		    # The node's name.
            "nodeName": "ip-10-1-0-10.ec2.internal",
			# The node's private IP. In some cases, this may be the same IP as
			# the publicIP. Used for cluster-internal communication.
            "privateIP": "10.1.0.10",
			# The node's public IP. Used to run boot scripts.
            "publicIP": "35.168.152.188"
        },
        {
            "nodeName": "ip-10-1-1-10.ec2.internal",
            "privateIP": "10.1.1.10",
            "publicIP": "34.236.94.133"
        },
        {
            "nodeName": "ip-10-1-2-10.ec2.internal",
            "privateIP": "10.1.2.10",
            "publicIP": "34.225.224.64"
        }
    ],

    # The list of worker nodes in the cluster.
    "workers": [
        {
            "nodeName": "ip-10-1-0-40.ec2.internal",
            "privateIP": "10.1.0.40",
            "publicIP": "34.239.205.162"
        },
        {
            "nodeName": "ip-10-1-1-40.ec2.internal",
            "privateIP": "10.1.1.40",
            "publicIP": "52.72.31.142"
        }
    ],

    # (Optional) The docker version to use.
    "dockerVersion": "17.03.2~ce-0~ubuntu-xenial",
    # (Optional) The Kubernetes version to use.
    "kubernetesVersion": "1.9.1",
    # (Optional) The etcd version to use. Preferred versions are:
    # k8s 1.9 => v3.1.10, k8s 1.8 => v3.0.17.
    "etcdVersion": "3.1.10",

    # (Optional) Directory under assets dir where etcd certificates will
    # be written.
    "etcdPKIDir": "pki/etcd",
    # (Optional) The Common Name of the etcd CA cert.
    "etcdCACommonName": "etcd-ca",
    # (Optional) The Common Name of the etcd client cett.
    "etcdClientCommonName": "etcd-client",
    # (Optional) The CA certificate expiry time. Default: 20 years.
    "etcdCACertExpiry": "175200h",

    # (Optional) Directory under assets dir where ssh keys for the nodes will
    # be written.
    "sshKeysDir": "pki/ssh",
    # (Optional) Directory under assets dir where node boot scripts will
    # be written.
    "scriptsDir": "scripts",

    "hooks": {
        # The name of a script to include as the first step in the generated
        # boot scripts, and will therefore run prior to anything else.
        # Assumed to be a fragment located under templates/hooks/preinstall/
        "preinstall": "aws.sh.j2",
        # Can be used to configure Kubernetes for a particular cloudprovider
        # (will be passed to apiserver, kubelet, and controller-manager).
        # For example, 'aws', 'azure', or 'openstack'.
        "cloudProvider": "aws",
        # A cloud-config to be used to configure the specified cloudprovider.
        # Some cloudproviders (aws) do not require a configuration file.
        # Assumed to be a fragment located under templates/hooks/cloudconfig/.
		# Note: if AWS VMs have been properly set up, no config is needed.
        "cloudProviderConfig": null
    }
}
```

For more details on the configuration format, refer to
the [source code](installer/cluster.py).

A couple of sample cluster definitions are available under [samples](samples).



## Prepare the installer
0. Make sure you have the following software installed:

   - `bash`
   - Python 3.5+
   - `pip`
   - [cfssl and cfssljson](https://pkg.cfssl.org/)
   - `ssh`
   - `ssh-keygen`

0. Install software prerequisites for the installer in a virtual environment:

        python3 -m venv .venv
        . .venv/bin/activate
        pip install -r requirements.txt


## Render cluster assets

Render *cluster assets*. The cluster assets consists of secrets (cluster token,
certificates, ssh keys) and boot scripts for each  master and worker. The assets
are written to `assets/` by default (run `--help` for flags).

        python -m installer render cluster.json

You can skim through the generated assets to convince yourself that they are
acceptable.


## Install cluster software
Use the installer to install the cluster by running the boot scripts (over SSH)
 against the master and workers declared in the cluster definition:


        python -m installer install cluster.json

By default all cluster machines are installed at once. One can also run the
installer against a subset of the machines in the cluster definition. For
example:

        python -m installer install cluster.json ip-10-1-0-10.ec2.internal

This can be useful if something went wrong with a node or it needs to be updated
or re-installed. Depending on the state of the node, it may be necessary to
first log in to the node and run `sudo kubeadm reset` to clear a prior
installation.


### Post-installation

Copy the `~/.kube/config` file from one of the masters, edit it to make sure
that the `server` field refers to the load-balancer's IP/hostname. You may then
interact as usual with the cluster using `kubectl`:

    kubectl --kubeconfig kubeconfig get nodes
    ... etc
