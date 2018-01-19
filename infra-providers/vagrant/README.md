This `Vagrant` file brings up VMs on which to run a HA Kubernetes cluster. 

The following VMs are started:

Three masters:
- `master0`: assigned private IP address `10.2.0.10`.
- `master1`: assigned private IP address `10.2.0.11`.
- `master2`: assigned private IP address `10.2.0.12`.

A load-balancer:
- `master-lb`: the masters, each of which are to be set up (by the installer) to
  host a Kubernetes API server (on port 6443), are fronted by a HAProxy load
  balancer running on the VM `master-lb` VM. It is assigned address
  `10.2.0.100`.

A worker:
- `worker0`: intended to host a Kubernetes worker VM, is started on `10.2.0.20`.


## Bring up the VMs

Provision VMs:

     vagrant up

When the machines are up, the load-balancer's status page can be viewed at
http://10.2.0.100:6444.


## Install Kubernetes
Once all VMs have booted, it is time to run the installer (refer to
the [README.md](../../README.md)).
