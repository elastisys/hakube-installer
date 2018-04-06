import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import logging
import os
import subprocess

from jinja2 import Environment, FileSystemLoader, Template

from . import fail
from . import ssh
from .token import ClusterToken

LOG = logging.getLogger(__name__)

MODULE_DIR = os.path.dirname(__file__)
CREATE_CA_CERT_SH = os.path.join(MODULE_DIR, "create-ca-cert.sh")
CREATE_CLIENT_CERT_SH = os.path.join(MODULE_DIR, "create-client-cert.sh")
CREATE_SERVER_CERT_SH = os.path.join(MODULE_DIR, "create-server-cert.sh")
CLUSTER_TOKEN_FILENAME = "cluster.token"
"""File name (under output-dir) to where cluster token is written."""

TEMPLATES_DIR = os.path.join(MODULE_DIR, "templates")
MASTER_SH_TEMPLATE = "master.sh.j2"
WORKER_SH_TEMPLATE = "worker.sh.j2"

CLUSTER_DEFAULTS = {
    # (Optional) A list of DNS names intended to be used to access the
    # API server. This should, for example, in the AWS case include
    # the FQDN of the public master loadbalancer, and any additional
    # domain names one would like to access it through.
    # All FQDNs in the list are added as subject alternate names to the
    # generated master certificates.
    "masterFQDNs":  [],
    # The IP address or FQDN (DNS name) of the master load-balancer.
    # This will be used internally within the cluster. For example, by
    # workers to connect to the apiservers.
    "masterLoadBalancerAddress": None,
    # (Optional) The username to use when logging in over SSH. Typically
    # 'ubuntu'.
    "sshLoginUser": "ubuntu",
    # (Optional) A private SSH login key to use when connecting to nodes.
    # Can be overridden on a per-node basis (see below).
    "sshLoginKey": None,
    # The list of master nodes in the cluster.
    "masters": None,
    # The list of worker nodes in the cluster.
    "workers": None,

    # (Optional) The docker version to use.
    "dockerVersion": "17.03.2~ce-0~ubuntu-xenial",
    # (Optional) The Kubernetes version to use.
    "kubernetesVersion": "1.10.0",
    # (Optional) The etcd version to use. Preferred versions are:
    # k8s 1.10 => 3.2.14+, k8s 1.9 => v3.1.10+, k8s 1.8 => v3.0.17.
    "etcdVersion": "3.2.14",

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
        "preinstall": None,
        # Can be used to configure Kubernetes for a particular cloudprovider
        # (will be passed to apiserver, kubelet, and controller-manager).
        # For example, 'aws', 'azure', or 'openstack'.
        "cloudProvider": None,
        # A cloud-config to be used to configure the specified cloudprovider.
        # Some cloudproviders (aws) do not require a configuration file.
        # Assumed to be a fragment located under templates/hooks/cloudconfig/
        "cloudProviderConfig": None
    }
}
"""Represents default cluster spec values."""




class ClusterDefinition:
    """A ClusterDefinition represents a cluster setup, from which cluster
    boot scripts can be `render`ed and `install`ed."""

    def __init__(self, path, assets_dir):
        """Create a ClusterDefinition from a spec at a given path.

        :param path: The file system path where the (JSON-formatted)
          cluster definition spec is stored.
        :param assets_dir: The file system path where cluster assets will
          be/have been written to.
        """
        self.assets_dir = assets_dir

        if not os.path.isfile(path):
            fail("cluster definition does not exist: {}".format(path))
        with open(path, "r") as f:
            input_spec = json.load(f)

        self.spec = copy.deepcopy(CLUSTER_DEFAULTS)
        self._apply(self.spec, input_spec)
        LOG.debug("effective cluster definition: %s", str(self))
        try:
            self._validate()
        except Exception as e:
            raise ValueError("cluster definition: {}".format(str(e)))


    def _validate(self):
        if not self.spec.get("masterLoadBalancerAddress"):
            raise ValueError("no masterLoadBalancerAddress specified")

        if not self.spec.get("masters"):
            raise ValueError("no master nodes specified")
        masters = self.spec["masters"]
        if not isinstance(masters, list):
            raise ValueError("'masters' expected to be a list")
        if len(masters) < 3:
            LOG.warn("a minimum of 3 masters is required for high-availability")
        for master in masters:
            try:
                self._validate_node(master)
            except ValueError as e:
                raise ValueError("master '{}': {}".format(master.get("nodeName"), str(e)))

        workers = self.spec.get("workers")
        if workers:
            if not isinstance(workers, list):
                raise ValueError("'workers' expected to be a list")
            for worker in workers:
                try:
                    self._validate_node(worker)
                except ValueError as e:
                    raise ValueError("worker '{}': {}".format(worker.get("nodeName"), str(e)))

        self._validate_unique_node_names(*masters, *workers)


    def _validate_node(self, node_def):
        if not node_def.get("nodeName"):
            raise ValueError("no nodeName specified")
        if not node_def.get("privateIP"):
            raise ValueError("no privateIP specified")
        if not node_def.get("publicIP"):
            raise ValueError("no publicIP specified")

        keypath = node_def.get("sshLoginKey") or self.spec.get("sshLoginKey")
        if not keypath:
            raise ValueError("no sshLoginKey specified (neither on node nor on cluster)")

    def _validate_unique_node_names(self, *nodes):
        names = [n["nodeName"] for n in nodes]
        if len(names) != len(set(names)):
            raise ValueError(
                "duplicate nodeName detected, nodeNames must be unique")

    def _apply(self, d1, d2):
        """Recursively apply all values of dict d2 to dict d1."""
        for k, v in d2.items():
            if type(v) == dict:
                if not k in d1 or d1[k] == None:
                    d1[k] = v
                else:
                    if type(d1[k]) != dict:
                        raise ValueError("input cluster attempts to set a value for key '{}' that is a dict, when it is expected to be of type {}".format(k, type(d1[k])))
                    self._apply(d1[k], v)
            else:
                d1[k] = v


    def __str__(self):
        return json.dumps(self.spec, indent=4)


    def token_path(self):
        return os.path.join(self.assets_dir, CLUSTER_TOKEN_FILENAME)

    def etcd_pki_dir(self):
        return os.path.join(self.assets_dir, self.spec["etcdPKIDir"])

    def ssh_keys_dir(self):
        return os.path.join(self.assets_dir, self.spec["sshKeysDir"])

    def scripts_dir(self):
        return os.path.join(self.assets_dir, self.spec["scriptsDir"])

    def script_path(self, nodename):
        """File-system location where installer script for the given node
        is (to be) stored.
        """
        return os.path.join(self.scripts_dir(), nodename + ".sh")

    def masters(self):
        """Return all master node declarations in the cluster definition."""
        return self.spec["masters"]

    def workers(self):
        """Return all worker node declarations in the cluster definition."""
        return self.spec["workers"]

    def all_nodes(self):
        """Return all node declarations in the cluster definition."""
        return self.masters() + self.workers()

    def get_nodes_by_name(self, node_names):
        """Return a given set of node declarations by nodeName.
        A `ValueError` is raised if a given node name does not exist in the
        cluster definition.
        """
        all_names = [n["nodeName"] for n in self.all_nodes()]
        for node_name in node_names:
            if not node_name in all_names:
                raise ValueError("referenced node '{}' is undefined".format(
                    node_name))
        return [n for n in self.all_nodes() if n["nodeName"] in node_names]


    def token_rendered(self):
        return os.path.exists(self.token_path())

    def etcd_file_exists(self, filename):
        """Return True if a given filename exists under the etcdPKIDir."""
        return os.path.exists(os.path.join(self.etcd_pki_dir(), filename))

    def etcd_ca_rendered(self):
        return (self.etcd_file_exists("ca.pem") and
                self.etcd_file_exists("ca-key.pem"))

    def etcd_client_rendered(self):
        return (self.etcd_file_exists("etcd-client.pem") and
                self.etcd_file_exists("etcd-client-key.pem"))

    def etcd_master_rendered(self, name):
        master_cert_files = [
            "etcd-{}-peer.pem".format(name),
            "etcd-{}-peer-key.pem".format(name),
            "etcd-{}-server.pem".format(name),
            "etcd-{}-server-key.pem".format(name),
        ]
        return all([self.etcd_file_exists(f) for f in master_cert_files])

    def ssh_privkey(self, nodename):
        """Return the filesystem path where a certain node's SSH private key
        is (to be) rendered."""
        return os.path.join(self.ssh_keys_dir(), "{}_rsa".format(nodename))

    def ssh_pubkey(self, nodename):
        """Return the filesystem path where a certain node's SSH public key
        is (to be) rendered."""
        return os.path.join(self.ssh_keys_dir(), "{}_rsa.pub".format(nodename))

    def sshkey_exists(self, filename):
        """Return True if a given filename exists under SSHKeysDir."""
        return os.path.exists(os.path.join(self.ssh_keys_dir(), filename))

    def sshkey_rendered(self, nodename):
        return (os.path.exists(self.ssh_privkey(nodename)) and
                os.path.exists(self.ssh_pubkey(nodename)))

    def node_script_rendered(self, nodename):
        """Return True if a given filename exists under ScriptsDir."""
        return os.path.exists(self.script_path(nodename))


    def _validate_software_prerequisites(self):
        """Validates that the software required to render cluster assets are
        installed on the local system."""
        software_validations = {
            "ssh": "which ssh",
            "ssh-keygen": "which ssh-keygen",
            "cfssl": "cfssl version",
        }
        for program, testcmd in software_validations.items():
            proc = subprocess.run(
                [testcmd], shell=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            if proc.returncode != 0:
                fail("{} does not appear to be installed".format(program))


    def render(self, overwrite_secrets=False, overwrite_scripts=True):
        """Renders assets for all nodes in the cluster definition.

        :param overwrite_secrets: Set to `True` if existing secrets (token,
          certs and keys) in the assets dir are to be overwritten.
        :param overwrite_scripts: Set to `True` if existing node bootscripts
          in the assets dir are to be overwritten.
        """
        self._validate_software_prerequisites()

        if overwrite_secrets or not self.token_rendered():
            # generate a new token
            self.cluster_token = ClusterToken().get()
            with open(self.token_path(), "w", encoding="utf-8") as f:
                f.write(self.cluster_token)
        # read token from file
        self.cluster_token = ClusterToken.parse(self.token_path()).get()

        if overwrite_secrets or not self.etcd_ca_rendered():
            LOG.info("generating etcd ca cert ...")
            cmd = "{script} --expiry={ca_expire} --output-dir={outdir} {common_name}".format(
                script=CREATE_CA_CERT_SH,
                ca_expire=self.spec["etcdCACertExpiry"],
                outdir=self.etcd_pki_dir(),
                common_name=self.spec["etcdCACommonName"])
            proc = subprocess.run(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.returncode != 0:
                fail("failed to generate etcd CA cert: {}".format(proc.stdout))

        if overwrite_secrets or not self.etcd_client_rendered():
            LOG.info("generating etcd client cert under %s ...", self.etcd_pki_dir())
            cmd = "{script} --output-dir={outdir} {common_name}".format(
                script=CREATE_CLIENT_CERT_SH, outdir=self.etcd_pki_dir(),
                common_name=self.spec["etcdClientCommonName"])
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.returncode != 0:
                fail("failed to generate etcd client cert: {}".format(proc.stdout))

        for master in self.spec["masters"]:
            name = master["nodeName"]
            if overwrite_secrets or not self.etcd_master_rendered(name):
                etcd_ip = master["privateIP"]
                LOG.info("generating etcd master cert for %s ...", name)
                cmd = "{script} --output-dir={outdir} {common_name} {ip}".format(
                    script=CREATE_SERVER_CERT_SH, outdir=self.etcd_pki_dir(),
                common_name="etcd-{}".format(name), ip=etcd_ip)
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if proc.returncode != 0:
                    fail("failed to generate etcd server cert: {}".format(proc.stdout))


        os.makedirs(self.ssh_keys_dir(), exist_ok=True)
        for node in self.all_nodes():
            nodename = node["nodeName"]
            if overwrite_secrets or not self.sshkey_rendered(nodename):
                if self.sshkey_rendered(nodename):
                    os.remove(self.ssh_privkey(nodename))
                    os.remove(self.ssh_pubkey(nodename))
                LOG.info("generating ssh key for %s ...", nodename)
                cmd = "ssh-keygen -b 2048 -t rsa -N '' -f {ssh_dir}/{node}_rsa -C {user}@{node}".format(ssh_dir=self.ssh_keys_dir(), user=self.spec["sshLoginUser"], node=nodename)
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if proc.returncode != 0:
                    fail("failed to generate ssh key: {}".format(proc.stdout))


        os.makedirs(self.scripts_dir(), exist_ok=True)
        env = Environment(loader=FileSystemLoader([TEMPLATES_DIR, self.assets_dir]))
        for master in self.spec["masters"]:
            nodename = master["nodeName"]
            if overwrite_scripts or not self.node_script_rendered(nodename):
                LOG.info("generating master script for %s ...", nodename)
                template = env.get_template(MASTER_SH_TEMPLATE)
                master_sh = self.script_path(nodename)
                with open(master_sh, "w", encoding="utf-8") as f:
                    f.write(template.render(
                        cluster=self.spec,
                        cluster_token=self.cluster_token,
                        master_name=nodename,
                        master=master
                    ))

        env = Environment(loader=FileSystemLoader([TEMPLATES_DIR, self.assets_dir]))
        for worker in self.spec["workers"]:
            nodename = worker["nodeName"]
            if overwrite_scripts or not self.node_script_rendered(nodename):
                LOG.info("generating worker script for %s ...", nodename)
                template = env.get_template(WORKER_SH_TEMPLATE)
                worker_sh = self.script_path(nodename)
                with open(worker_sh, "w", encoding="utf-8") as f:
                    f.write(template.render(
                        cluster=self.spec,
                        cluster_token=self.cluster_token,
                        worker_name=nodename,
                        worker=worker
                    ))


    def install(self, targeted_nodes=None, log_dir="logs"):
        """Runs the install scripts (over SSH) for the given list of nodes
        or for all nodes in the cluster definition if no nodes are specified.

        :param nodes: A list of node declarations  that are to be installed.
          May be `None`, in which case all nodes in the cluster definition
          are installed.
        :param log_dir: The file system directory where the install script
          execution logs will be written.
        """
        targeted_nodes = targeted_nodes or self.all_nodes()
        future_to_node = {}
        self._ensure_sshkeys_present(targeted_nodes)
        self._ensure_bootscripts_rendered(targeted_nodes)
        os.makedirs(log_dir, exist_ok=True)
        with ThreadPoolExecutor(max_workers=20) as executor:
            for node in self.all_nodes():
                if not node in targeted_nodes:
                    continue
                node_installer = self._create_install_task(node, log_dir)
                future_to_node[executor.submit(node_installer.run)] = node

            for future in concurrent.futures.as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    exitcode = future.result()
                    if exitcode == 0:
                        LOG.info("%s installer finished", node["nodeName"])
                    else:
                        LOG.error("%s installer failed (exit code %d)",
                                  node["nodeName"], exitcode)
                except Exception as e:
                    LOG.error(
                        "%s installer failed: %s", node["nodeName"], str(e))

    def _ensure_sshkeys_present(self, nodes):
        for node in nodes:
            if not self.sshkey_rendered(node["nodeName"]):
                raise RuntimeError("ssh key does not exist: {}".format(self.ssh_privkey(node["nodeName"])))

    def _ensure_bootscripts_rendered(self, nodes):
        for node in nodes:
            if not os.path.isfile(self.script_path(node["nodeName"])):
                raise RuntimeError("no boot script found for {} under assets directory -- did you run render?".format(node["nodeName"]))


    def _ssh_login_key(self, node):
        """Determines the SSH login key to use for a node."""
        key_path = self.spec.get("sshLoginKey")
        if "sshLoginKey" in node:
            key_path = node["sshLoginKey"]

        return os.path.abspath(os.path.expanduser(key_path))

    def _create_install_task(self, node, log_dir):
        nodename = node["nodeName"]
        log_path= os.path.join(log_dir, nodename + ".log")
        ssh_key = self._ssh_login_key(node)
        LOG.debug("using ssh key: %s", ssh_key)
        script_path = self.script_path(nodename)
        return ssh.SSHCommand(
            host=node["publicIP"], username=self.spec["sshLoginUser"],
            private_key=ssh_key, script_path=script_path, output_path=log_path)
