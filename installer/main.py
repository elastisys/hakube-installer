import argparse
import logging
import os
import sys
import traceback

from . import fail
from . import cluster

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(threadName)s [%(levelname)5.5s] %(message)s")
LOG = logging.getLogger(__name__)


def render(args):
    """Executes the `render` subcommand."""
    assets_dir = os.path.abspath(args.assets_dir)
    os.makedirs(assets_dir, exist_ok=True)
    LOG.info("rendering assets to %s", assets_dir)

    cluster_path = os.path.abspath(args.cluster_def)
    clusterdef = cluster.ClusterDefinition(cluster_path, assets_dir)
    clusterdef.render(
        overwrite_secrets=args.overwrite_secrets,
        overwrite_scripts=args.overwrite_scripts)


def install(args):
    """Executes the `install` subcommand."""
    assets_dir = os.path.abspath(args.assets_dir)
    cluster_path = os.path.abspath(args.cluster_def)
    clusterdef = cluster.ClusterDefinition(cluster_path, assets_dir)

    targeted_nodes = clusterdef.get_nodes_by_name(args.nodes)
    clusterdef.install(targeted_nodes)


def cli():
    parser = argparse.ArgumentParser(
        prog="installer",
        description="An installer that stands up a highly available "
        "Kubernetes cluster")
    subparsers = parser.add_subparsers(help="subcommands")

    parser_render = subparsers.add_parser(
        "render", help="Renders all necessary assets (certificates and "
        "scripts) for bringing up the cluster")
    parser_render.add_argument(
        "cluster_def", metavar="<cluster-json>",
        help="A JSON-formatted cluster definition.")
    parser_render.add_argument(
        "--assets-dir", metavar="<PATH>", dest="assets_dir",
        default="assets", help="Directory to which cluster scripts and certs "
        "will be written. Default: assets")
    parser_render.add_argument(
        "--overwrite-secrets", dest="overwrite_secrets", action="store_true",
        default=False,
        help="Set if existing secrets (certs and keys) in the assets dir "
        "are to be overwritten. Default behavior: don't overwrite.")
    parser_render.add_argument(
        "--no-overwrite-scripts", dest="overwrite_scripts",
        action="store_false", default=True,
        help="Set if existing boot scripts in the assets dir are NOT to be "
        "overwritten. Default behavior: overwrite.")
    parser_render.set_defaults(handler=render)

    parser_install = subparsers.add_parser(
        "install", help="installs and configures the cluster nodes from "
        "previously rendered scripts and assets")
    parser_install.add_argument(
        "cluster_def", metavar="<cluster-json>",
        help="A JSON-formatted cluster definition.")
    parser_install.add_argument(
        "nodes", metavar="NODE", nargs="*",
        help="Only run install against a particular subset of machines in "
        "the cluster definition file. Accepts a list of zero or more "
        "nodeNames. The default is to install all machines in cluster the "
        "definition file.")
    parser_install.add_argument(
        "--assets-dir", metavar="<PATH>", dest="assets_dir",
        default="assets", help="Directory where cluster scripts and certs have been rendered. Default: assets")
    parser_install.set_defaults(handler=install)

    args = parser.parse_args()
    if not hasattr(args, 'handler'):
        parser.print_help()
        sys.exit(1)

    try:
        args.handler(args)
    except Exception as e:
        traceback.print_exc()
        fail(str(e))
