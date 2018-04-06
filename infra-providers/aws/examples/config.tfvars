aws_access_key = "ABC...123"
aws_secret_key = "DEF...456"
region       = "eu-west-1"
cluster_name = "kube-demo"

# specify vpc_id to make use of an existing VPC
# vpc_id       = "vpc-ffc21e99"
# CIDR block to assign if a new VPC is to be created
vpc_address_range = "10.0.20.0/16"

availability_zones = {
  "eu-west-1a" = {
    "subnet_cidr_block" = "10.0.20.0/24"
  }

  "eu-west-1b" = {
    "subnet_cidr_block" = "10.0.21.0/24"
  }

  "eu-west-1c" = {
    "subnet_cidr_block" = "10.0.22.0/24"
  }
}

# IP addresses allowed to access masters
master_firewall_allowed_ips = ["1.2.3.4/32"]
# IP addresses allowed to access workers
worker_firewall_allowed_ips = ["1.2.3.4/32"]

num_masters = "3"
num_workers = "6"

master_instance_type     = "t2.medium"
master_data_disk_size_gb = "50"
worker_instance_type     = "t2.xlarge"


ssh_public_key_path  = "~/./ssh/demokube_rsa.pub"
ssh_private_key_path = "~/./ssh/demokube_rsa"
