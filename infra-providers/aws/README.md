# AWS EC2 infrastructure provider

The AWS EC2 Terraform configuration requires some input in order to provision
servers. The set of parameters is quite large but most of the parameters are
optional and can safely be left out.

A few parameters, like cloud credentials, are mandatory though, and
need to be passed to Terraform. Terraform will prompt the user for all
mandatory parameters. This can be a bit tedious, and one can therefore place
mandatory parameters in
[variable files](https://www.terraform.io/intro/getting-started/variables.html)
which are passed with one or more `-var-file` flags.

To view all available configuration options see [main.tf](./main.tf).

This infrastructure-provider provisions the following infrastructure, all in the
selected region:

- A [VPC (Virtual Private Cloud)](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html).
  That is, a virtual network. It is created with several subnets --  one for
  each availability zone in the region (a subnet is always tied to a single AZ).
- A key pair from the specified public SSH key, which is used to launch the
  instances.
- Security groups that further restrict port access to instances: one for the
  `kubemaster`s, and one to be used by Kubernetes cluster members.
- An
  [IAM instance profile](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) which
  is used to delegate AWS access credentials to the created instances (allowing
  them to access AWS APIs).
- A collection of `kubemaster` instances (specified by `num_master_nodes`).
  The master instances will be spread over the availability zones.
  For high-availability, at least 3 needs to be created. No software apart from
  a baseline Ubuntu OS is installed.

- A collection of `kubeworker`instances (specified by `num_worker_nodes`).
  No software apart from a baseline Ubuntu OS is installed.

- One internal Elastic Load Balancer (ELB) fronting the `masters` to be used 
  internally by the cluster nodes.

- One internet-facing Elastic Load Balancer (ELB) fronting the `masters` to be 
  used from the internet to access Kubernetes API server (for example, via 
  `kubectl`).

Run:

    # initialize the working directory
    terraform init infra-providers/aws

    # plan the provsioning (this is a dry-run that won't execute anything)
    terraform plan -var-file config.json infra-providers/aws

    # execute the provisioning plan
    terraform apply -var-file config.json infra-providers/aws


### Output
When `terraform apply` finishes, it outputs information about the infrastructure
it produced. Some of these output items need to be passed to the installer.
These include:

  - `master_public_ips`: needs to be set in the `publicIP` field for each master
    in the cluster definition.
  - `master_private_ips`: needs to be set in the `privateIP` field for each
    master in the cluster definition.
  - `worker_public_ips`: needs to be set in the `publicIP` field for each worker
    in the cluster definition.
  - `worker_private_ips`: needs to be set in the `privateIP` field for each
    worker in the cluster definition.
  - `master_internal_loadbalancer_fqdn`: needs to be set in the
    `masterLoadBalancerAddress` field in the cluster definition.
  - `master_public_loadbalancer_fqdn`: needs to be added to the list of master 
     FQDNs in `masterFQDNs`.

### Install Kubernetes
Once all VMs have booted, it is time to run the installer (refer to
the [README.md](../../README.md)).
