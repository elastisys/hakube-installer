#
# A provisioner that sets up Ubuntu VMs for a HA Kubernetes cluster in AWS.
#
# Note: The VMs are only provisioned, they need to have the right software
#       installed before being operational.
#

#
# Mandatory variables
#

variable "aws_access_key" {
    description = "Your AWS Access Key ID. https://console.aws.amazon.com/iam/home?#/users"
}

variable "aws_secret_key" {
    description = "Your AWS Secret Access Key. https://console.aws.amazon.com/iam/home?#/users"
}


variable "aws_region" {
    description = "Region where the infrastructure is to be created. For example, 'us-east-1'. See http://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region"
}

variable "cluster_name" {
    description = "A name that should describe the purpose of the cluster (for example, 'prodkube'). Will be used to tag created resources (and distinguish cluster resources when multiple clusters have been set up)."
}

#
# Optional variables
#

variable "vpc_name" {
    description = "The name of the virtual network. Default: [cluster_name]-vpc"
    default     = ""
}

variable "vpc_address_range" {
    description = "The IP address range for the virtual network onto which VMs are attached. Must not clash with kubernetes pod IP range or service IP range."
    default     = "10.1.0.0/16"
}

variable "vpc_firewall_port_openings" {
    description = "Virtual network firewall port openings on. The network must admit access to all ports that are to be exposed by VMs in the network."
    default     = ["22", "6443"]
}

variable "vpc_firewall_allowed_ips" {
    description = "A list of allowed source addresses for firewall openings. Specified as CIDR ranges (192.0.0.0/8)."
    default     = ["0.0.0.0/0"]
    type        = "list"
}

variable "instance_tenancy" {
    description = "Describes if instances within the VPC are to run on dedicated or shared hardware. See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html"
    default     = "default"
}

variable "subnet_name_prefix" {
    description = "The name prefix to use for created subnets within the virtual network. One subnet will be created for each availabiltiy zone in the region. Default: [cluster_name]-subnet"
    default     = ""
}

variable "subnet_cidr_bits" {
    description = "The size of each subnet in bits. If set to 8, each subnet that gets created (one per availability zone) is given a slice of the VPC network with room for 2^8 = 256 hosts. If the VPC network range is 10.1.0.0/16, the first subnet would be 10.1.0.0/24, the second would be 10.1.1.0/24, the third would be 10.1.2.0/24, etc."
    default     = "8"
}

variable "keypair_name" {
    description = "The name of the keypair to use when launching VMs. Default: [cluster_name]-sshkey"
    default     = ""
}

variable "iam_role_name" {
    description = "The name of the IAM instance profile role to create. Default: [cluster_name]-iam-role"
    default     = ""
}

variable "iam_profile_name" {
    description = "The name of the IAM instance profile to create. Default: [cluster_name]-iam-profile"
    default     = ""
}

variable "ubuntu_image" {
    description = "The Ubuntu image to use. Note: this is not the AMI id."
    default     = "ubuntu-xenial-16.04-amd64"
}

variable "vm_user" {
    description = "The admin user of created VMs."
    default     = "ubuntu"
}

variable "num_masters" {
        description = "The number of master nodes to create. Needs to be at least three for high-availability."
    default     = "3"
}

variable "master_name_prefix" {
    description = "The name prefix to use for master VMs. Default: [cluster_name]-master. An index is appended to the prefix for each VM so that it becomes [cluster_name]-master-[index]."
    default     = ""
}

variable "master_instance_type" {
    description = "The instance type to use for the Kubernetes master VM."
    default     = "t2.medium"
}

variable "master_ebs_optimized" {
    description = "Set to true to use SSD disks. Note: not all instance types can be run as EBS-optimized."
    default     = false
}

variable "master_subnet_ip_start_index" {
    description = "The IP address start index to use for master VMs in each subnet (a few IP addresses at the beginning of each subnet are typically reserved). Each master will be assigned a private IP address with a given index from its subnet address range. Assuming a 3-master cluster, with start index of 10, master1 may be assigned a private IP of 10.1.0.10, master2 may be assigned a private IP of 10.1.1.10, and master3 may be assigned a private IP address of 10.1.2.10 (note that the masters will be spread across AZs and may therfore end up on different subnets)."
    default     = "10"
}

variable "master_firewall_port_openings" {
    description = "Firewall port openings on the master."
    default     = ["22", "6443"]
}

variable "master_firewall_allowed_ips" {
    description = "A list of allowed source addresses for firewall openings. Specified as CIDR ranges (192.0.0.0/8)."
    default     = ["0.0.0.0/0"]
}

variable "master_data_disk_size_gb" {
    description = "The size (in GB) of the master etcd data disk."
    default     = "20"
}


variable "num_workers" {
    description = "The number of worker nodes to create."
    default     = "2"
}

variable "worker_name_prefix" {
    description = "The name prefix to use for worker VMs. Default: [cluster_name]-worker. An index is appended to the prefix for each VM so that it becomes [cluster_name]-worker-[index]."
    default     = ""
}

variable "worker_instance_type" {
    description = "The instance type to use for the worker VMs."
    default     = "t2.medium"
}

variable "worker_ebs_optimized" {
    description = "Set to true to use SSD disks. Note: not all instance types can be run as EBS-optimized."
    default     = false
}

variable "worker_subnet_ip_start_index" {
    description = "The IP address start index to use for worker VMs. Each worker will be assigned a private IP address with a given index from its subnet address range. Assuming a 3-worker cluster, with start index of 40, worker1 may be assigned a private IP of 10.1.0.40, worker2 may be assigned a private IP of 10.1.1.41, and worker3 may be assigned a private IP address of 10.1.2.42 (note that the workers will be spread across AZs and may therfore end up on different subnets. A few IP addresses in the beginning of each subnet are typically reserved."
    default     = "40"
}

variable "worker_firewall_port_openings" {
    description = "Firewall port openings on the worker."
    default     = ["22"]
}

variable "worker_firewall_allowed_ips" {
    description = "A list of allowed source addresses for firewall openings. Specified as CIDR ranges (192.0.0.0/8)."
    default     = ["0.0.0.0/0"]
}

variable "ssh_public_key_path" {
    description = "Local file path to public SSH login key for created VMs. Default: ~/.ssh/id_rsa.pub"
    default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_private_key_path" {
    description = "Local file path to private SSH login key for created VMs. Default: ~/.ssh/id_rsa"
    default     = "~/.ssh/id_rsa"
}

#
# Computed default values
#

locals {
    default_vpc_name    = "${var.cluster_name}-vpc"
    default_subnet_name_prefix = "${var.cluster_name}-subnet"
    default_key_name    = "${var.cluster_name}-sshkey"
    default_iam_role    = "${var.cluster_name}-iam-role"
    default_iam_profile = "${var.cluster_name}-iam-profile"
    default_master_name = "${var.cluster_name}-master"
    default_worker_name = "${var.cluster_name}-worker"

    vpc_name            = "${var.vpc_name != "" ? var.vpc_name : local.default_vpc_name}"
    vpc_gateway_name    = "${local.vpc_name}-gateway"
    route_table_name    = "${local.vpc_name}-rt"
    subnet_name_prefix  = "${var.subnet_name_prefix != "" ? var.subnet_name_prefix : local.default_subnet_name_prefix}"

    key_name            = "${var.keypair_name != "" ? var.keypair_name : local.default_key_name}"
    iam_role_name       = "${var.iam_role_name != "" ? var.iam_role_name : local.default_iam_role}"
    iam_profile_name    = "${var.iam_profile_name != "" ? var.iam_profile_name : local.default_iam_profile}"
    iam_role_policy     = "${local.iam_role_name}-policy"

    master_name_prefix  = "${var.master_name_prefix != "" ? var.master_name_prefix : local.default_master_name}"

    master_sg_name      = "${var.cluster_name}-master-sg"
    master_loadbalancer_name = "${var.cluster_name}-master-lb"

    cluster_sg_name     = "${var.cluster_name}-sg"

    worker_name_prefix  = "${var.worker_name_prefix != "" ? var.worker_name_prefix : local.default_worker_name}"
    worker_sg_name      = "${var.cluster_name}-worker-sg"

    # Kubernetes cluster tags.
    # Unless a cloud-config is specified which specifies a "legacy" tag
    #   [Global]
    #   KubernetesClusterTag=my-cluster
    #   KubernetesClusterID=my-cluster
    # the k8s aws provider reads the cluster name from a tag named
    # kubernetes.io/cluster/<cluster-name>. This allows a single AZ to
    # host multiple clusters. The value must be 'owned' or 'shared'.
    # see https://github.com/kubernetes/kubernetes/blob/v1.8.3/pkg/cloudprovider/providers/aws/tags.go#L108-L109
    cluster_tags            = "${map("kubernetes.io/cluster/${var.cluster_name}", "owned")}"
}

#
# Resources
#

terraform {
    required_version = ">= 0.11.0"
}

provider "aws" {
    version    = "~> 1.6"

    access_key = "${var.aws_access_key}"
    secret_key = "${var.aws_secret_key}"
    region     = "${var.aws_region}"
}

# lists all availability zones in the region
data "aws_availability_zones" "available" {}

locals {
    az_names = "${data.aws_availability_zones.available.names}"
}

# create a virtual network
resource "aws_vpc" "net" {
    cidr_block           = "${var.vpc_address_range}"
    instance_tenancy     = "${var.instance_tenancy}"
    # support aws DNS within the VPC. as an example, this allows instances
    # to resolve aws-provided private DNS names (such as EFS file system
    # DNS names)
    enable_dns_support   = true
    enable_dns_hostnames = true

    tags             = "${merge(local.cluster_tags, map("Name", "${local.vpc_name}"))}"
}

# Access control for the virtual network
resource "aws_network_acl" "vpc_acl" {
    vpc_id = "${aws_vpc.net.id}"

    tags = "${merge(local.cluster_tags, map("Name", "${local.vpc_name}"))}"
}

# Firewall rules for the virtual network: opens the specified ports for each allowed IP range
resource "aws_network_acl_rule" "network_rule" {
    count = "${length(var.vpc_firewall_port_openings) * length(var.vpc_firewall_allowed_ips)}"

    network_acl_id = "${aws_network_acl.vpc_acl.id}"
    rule_number    = "${100 + count.index}"
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "${var.vpc_firewall_allowed_ips[count.index / length(var.vpc_firewall_port_openings)]}"
    from_port      = "${var.vpc_firewall_port_openings[count.index % length(var.vpc_firewall_port_openings)]}"
    to_port        = "${var.vpc_firewall_port_openings[count.index % length(var.vpc_firewall_port_openings)]}"
}

# create one subnet in the virtual network for each availability zone
resource "aws_subnet" "subnets" {
    count = "${length(local.az_names)}"

    vpc_id     = "${aws_vpc.net.id}"
    availability_zone = "${local.az_names[count.index]}"
    # give each subnet a slice of the specified size (in bits)
    cidr_block = "${cidrsubnet(var.vpc_address_range, var.subnet_cidr_bits, count.index)}"

    tags       = "${merge(local.cluster_tags, map("Name", "${local.subnet_name_prefix}-${local.az_names[count.index]}"))}"
}

locals {
    subnet_ids = "${aws_subnet.subnets.*.id}"
}

# add internet gateway to VPC (to allow internet to reach vpc)
resource "aws_internet_gateway" "gateway" {
    vpc_id = "${aws_vpc.net.id}"
    tags   = "${merge(local.cluster_tags, map("Name", "${local.vpc_gateway_name}"))}"
}

# add route table and associate with subnet (to allow internet to reach subnet)
resource "aws_route_table" "rt" {
    vpc_id = "${aws_vpc.net.id}"

    route {
	cidr_block = "0.0.0.0/0"
	gateway_id = "${aws_internet_gateway.gateway.id}"
    }

    tags   = "${merge(local.cluster_tags, map("Name", "${local.route_table_name}"))}"
}

# associate route table with each subnet (one for each AZ)
resource "aws_route_table_association" "rtassociation" {
    count = "${length(local.az_names)}"

    subnet_id      = "${element(local.subnet_ids, count.index)}"
    route_table_id = "${aws_route_table.rt.id}"
}


# The IAM role to use for launched instances
resource "aws_iam_role" "instance_role" {
    name = "${local.iam_role_name}"
    path = "/"

    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# The access grants to give the IAM role.
resource "aws_iam_role_policy" "test_policy" {
    name = "${local.iam_role_policy}"
    role = "${aws_iam_role.instance_role.id}"

    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "ec2:*",
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": "elasticloadbalancing:*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

# IAM instance profile to use when launching VMs
resource "aws_iam_instance_profile" "iam_profile" {
    name  = "${local.iam_profile_name}"
    role  = "${aws_iam_role.instance_role.name}"
}


# create a key pair from public SSH key
resource "aws_key_pair" "sshkey" {
    key_name   = "${local.key_name}"
    public_key = "${file(pathexpand("${var.ssh_public_key_path}"))}"
}


# locate Ubuntu AMI
data "aws_ami" "ubuntu" {
    most_recent = true

    filter {
	name   = "name"
	values = ["ubuntu/images/hvm-ssd/${var.ubuntu_image}-server-*"]
    }

    filter {
	name   = "virtualization-type"
	values = ["hvm"]
    }

    owners = ["099720109477"] # Canonical
}

# create security group to use for inter-node communication in kubernetes cluster
resource "aws_security_group" "cluster_sg" {
    name        = "${local.cluster_sg_name}"
    description = "${var.cluster_name} - allow k8s nodes to speak freely amongst themselves"
    vpc_id      = "${aws_vpc.net.id}"

    # all instances with this security group can access any other instance in
    # this security group on any port
    ingress {
	self        = true
	from_port   = 0
	to_port     = 65535
	protocol    = "tcp"
    }
    ingress {
	self        = true
	from_port   = 0
	to_port     = 65535
	protocol    = "udp"
    }

    # outgoing traffic is allowed to go anywhere
    egress {
	from_port       = 0
	to_port         = 0
	protocol        = "-1"
	cidr_blocks     = ["0.0.0.0/0"]
    }

    tags = "${merge(local.cluster_tags, map("Name", "${local.cluster_sg_name}"))}"
}

# create a security group that can be assigned to an EFS store to grant
# all kubernetes nodes access
resource "aws_security_group" "nfs_sg" {
    name        = "${var.cluster_name}-nfs-sg"
    description = "${var.cluster_name} - allow k8s nodes to access EFS"
    vpc_id      = "${aws_vpc.net.id}"

    ingress {
	security_groups = ["${aws_security_group.cluster_sg.id}"]
	from_port       = 2049
	to_port         = 2049
	protocol        = "tcp"
    }

    tags = "${merge(local.cluster_tags, map("Name", "${var.cluster_name}-nfs-sg"))}"
}


# create security group for masters
resource "aws_security_group" "master_sg" {
    name        = "${local.master_sg_name}"
    description = "${var.cluster_name} master firewall rules"
    vpc_id      = "${aws_vpc.net.id}"

    tags = "${merge(local.cluster_tags, map("Name", "${local.master_sg_name}"))}"
}

# create firewall port openings for masters
resource "aws_security_group_rule" "master_ingress_rules" {
    count = "${length(var.master_firewall_port_openings) * length(var.master_firewall_allowed_ips)}"


    security_group_id = "${aws_security_group.master_sg.id}"
    type              = "ingress"
    from_port         = "${var.master_firewall_port_openings[count.index % length(var.master_firewall_port_openings)]}"
    to_port           = "${var.master_firewall_port_openings[count.index % length(var.master_firewall_port_openings)]}"
    protocol          = "tcp"
    cidr_blocks       = ["${var.master_firewall_allowed_ips[count.index / length(var.master_firewall_port_openings)]}"]
}

# masters should be able to reach the public internet
resource "aws_security_group_rule" "master_egress_rules" {
    security_group_id = "${aws_security_group.master_sg.id}"
    type              = "egress"
    from_port         = "0"
    to_port           = "65535"
    protocol          = "-1"
    cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_instance" "masters" {
    count = "${var.num_masters}"

    depends_on = ["aws_internet_gateway.gateway"]

    ami           = "${data.aws_ami.ubuntu.id}"
    instance_type = "${var.master_instance_type}"
    tenancy       = "${var.instance_tenancy}"
    ebs_optimized = "${var.master_ebs_optimized}"

    key_name               = "${local.key_name}"
    vpc_security_group_ids = ["${aws_security_group.master_sg.id}", "${aws_security_group.cluster_sg.id}"]
    iam_instance_profile   = "${aws_iam_instance_profile.iam_profile.name}"

    # spread instances over available subnets
    subnet_id     = "${element(aws_subnet.subnets.*.id, count.index)}"
    associate_public_ip_address = false
    private_ip = "${cidrhost(element(aws_subnet.subnets.*.cidr_block, count.index), var.master_subnet_ip_start_index + (count.index / length(aws_subnet.subnets.*.id)) )}"

    # the kubernetes.io/role/master master tag can be useful. for example,
    # aws dynamic volume provisioner uses it to not create a volume in an
    # AZ with only master nodes:
    #   https://github.com/kubernetes/kubernetes/pull/41702
    tags = "${merge(local.cluster_tags, map("Name", "${local.master_name_prefix}-${count.index}", "kubernetes.io/role/master", "true"))}"
}

# create elastic IP for master (regular public IPs do not survive restarts)
resource "aws_eip" "master_eips" {
    count = "${var.num_masters}"

    instance = "${element(aws_instance.masters.*.id, count.index)}"
    vpc      = true
}

# master data EBS volume
resource "aws_ebs_volume" "master_data_disks" {
    count = "${var.num_masters}"

    availability_zone = "${element(aws_instance.masters.*.availability_zone, count.index)}"
    type = "standard"
    size = "${var.master_data_disk_size_gb}"

    tags = "${merge(local.cluster_tags, map("Name", "${local.master_name_prefix}-${count.index}-etcd-disk"))}"
}


# associate EBS data volume with master VM
resource "aws_volume_attachment" "master_vols" {
    count = "${var.num_masters}"

    device_name = "/dev/sdh"
    volume_id   = "${element(aws_ebs_volume.master_data_disks.*.id, count.index)}"
    instance_id = "${element(aws_instance.masters.*.id, count.index)}"

    # force volume detach on destroy
    force_detach = true
}

# master network loadbalancer
resource "aws_lb" "master_lb" {
    name               = "${local.master_loadbalancer_name}"
    load_balancer_type = "network"
    subnets            = ["${aws_subnet.subnets.*.id}"]

    # connection idle timeout in seconds
    idle_timeout    = 60

    tags = "${merge(local.cluster_tags, map("Name", "${local.master_loadbalancer_name}"))}"
}

# master LB backend (target group)
resource "aws_lb_target_group" "masters" {
    name     = "${local.master_loadbalancer_name}-backends"
    port     = 6443
    protocol = "TCP"
    vpc_id   = "${aws_vpc.net.id}"
}

# master LB frontend
resource "aws_lb_listener" "lb_frontend" {
    load_balancer_arn = "${aws_lb.master_lb.arn}"
    port              = "6443"
    protocol          = "TCP"

    default_action {
	target_group_arn = "${aws_lb_target_group.masters.arn}"
	type             = "forward"
    }
}

# add masters to LB backend (target group)
resource "aws_lb_target_group_attachment" "masters" {
    count = "${var.num_masters}"

    target_group_arn = "${aws_lb_target_group.masters.arn}"
    target_id        = "${element(aws_instance.masters.*.id, count.index)}"
    port             = 6443
}

# versioning of the null provider
provider "null" {
    version = "~> 1.0"
}

# Log onto the VM and create an ext4 file system on the data disk
resource "null_resource" "master_bootstraps" {
    count = "${var.num_masters}"

    # need both volume mounted and public ip before running ssh bootscript
    depends_on = [
	"aws_volume_attachment.master_vols",
	"aws_eip.master_eips"
    ]

    # changes to volume attachment requires re-provisioning
    triggers {
	created = "${element(aws_volume_attachment.master_vols.*.device_name, count.index)}"
    }

    connection {
	type        = "ssh"
	host        = "${element(aws_eip.master_eips.*.public_ip, count.index)}"
	user        = "${var.vm_user}"
	agent       = "false"
	private_key = "${file(var.ssh_private_key_path)}"
	timeout     = "5m"
    }

    # NOTE: even though we name the device to /dev/sdh in EC2, it appears as
    #       though the instance internally assigns a different device name
    #       (/dev/xvdh). See
    #  http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
    provisioner "remote-exec" {
	inline = [
	    # format etcd data volume
	    "yes | sudo mkfs.ext4 /dev/xvdh",
	    # mount etcd data volume
	    "sudo mkdir -p /var/lib/etcd",
	    "sudo mount /dev/xvdh /var/lib/etcd",
	    # make sure disk is remounted on reboot
	    "echo /dev/xvdh /var/lib/etcd ext4 defaults,nofail 0 0 | sudo tee -a /etc/fstab"
	]
    }
}

# create security group for masters
resource "aws_security_group" "worker_sg" {
    name        = "${local.worker_sg_name}"
    description = "${var.cluster_name} worker firewall rules"
    vpc_id      = "${aws_vpc.net.id}"

    tags = "${merge(local.cluster_tags, map("Name", "${local.worker_sg_name}"))}"
}

# create firewall port openings for workers
resource "aws_security_group_rule" "worker_ingress_rules" {
    count = "${length(var.worker_firewall_port_openings) * length(var.worker_firewall_allowed_ips)}"


    security_group_id = "${aws_security_group.worker_sg.id}"
    type              = "ingress"
    from_port         = "${var.worker_firewall_port_openings[count.index % length(var.worker_firewall_port_openings)]}"
    to_port           = "${var.worker_firewall_port_openings[count.index % length(var.worker_firewall_port_openings)]}"
    protocol          = "tcp"
    cidr_blocks       = ["${var.worker_firewall_allowed_ips[count.index / length(var.worker_firewall_port_openings)]}"]
}

# workers should be able to reach the public internet
resource "aws_security_group_rule" "worker_egress_rules" {
    security_group_id = "${aws_security_group.worker_sg.id}"
    type              = "egress"
    from_port         = "0"
    to_port           = "65535"
    protocol          = "-1"
    cidr_blocks       = ["0.0.0.0/0"]
}


# create worker VMs
resource "aws_instance" "workers" {
    count = "${var.num_workers}"

    depends_on = ["aws_internet_gateway.gateway"]

    ami           = "${data.aws_ami.ubuntu.id}"
    instance_type = "${var.worker_instance_type}"
    tenancy       = "${var.instance_tenancy}"
    ebs_optimized = "${var.worker_ebs_optimized}"

    key_name               = "${local.key_name}"
    vpc_security_group_ids = ["${aws_security_group.worker_sg.id}", "${aws_security_group.cluster_sg.id}"]
    iam_instance_profile   = "${aws_iam_instance_profile.iam_profile.name}"

    # spread instances over available subnets
    subnet_id     = "${element(aws_subnet.subnets.*.id, count.index)}"
    associate_public_ip_address = true
    private_ip = "${cidrhost(element(aws_subnet.subnets.*.cidr_block, count.index), var.worker_subnet_ip_start_index + (count.index / length(aws_subnet.subnets.*.id)) )}"

    tags = "${merge(local.cluster_tags, map("Name", "${local.worker_name_prefix}-${count.index}"))}"
}

#
# Output
#

output "master_public_ips" {
    value = "${aws_eip.master_eips.*.public_ip}"
}

output "master_private_ips" {
    value = "${aws_instance.masters.*.private_ip}"
}

output "worker_public_ips" {
  value = "${aws_instance.workers.*.public_ip}"
}

output "worker_private_ips" {
    value = "${aws_instance.workers.*.private_ip}"
}

output "cluster_security_group_id" {
    value = "${aws_security_group.cluster_sg.id}"
}

output "vpc_name" {
    value = "${local.vpc_name}"
}

output "vpc_id" {
    value = "${aws_vpc.net.id}"
}

output "subnet_ids" {
    value = "${aws_subnet.subnets.*.id}"
}

output "subnet_cidr_blocks" {
    value = "${aws_subnet.subnets.*.cidr_block}"
}

output "iam_instance_profile_arn" {
    value = "${aws_iam_instance_profile.iam_profile.arn}"
}

output "keypair_name" {
    value = "${local.key_name}"
}

output "ubuntu_ami" {
    value = "${data.aws_ami.ubuntu.id}"
}

output "master_loadbalancer_fqdn" {
    value = "${aws_lb.master_lb.dns_name}"
}

output "vm_user" {
    value = "${var.vm_user}"
}

output "ssh_private_key" {
    value = "${var.ssh_private_key_path}"
}
