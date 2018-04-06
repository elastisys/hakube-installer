import logging
import subprocess
import time

LOG = logging.getLogger(__name__)

class SSHCommand:
    """An script executor that runs a script on a remote host over SSH."""

    def __init__(self, host, username, private_key, script_path, output_path):
        """Create a SSHCommand instance that executes a given script on a
        given host over SSH.

        :param host: Destination host.
        :param username: Login user.
        :param private_key: Path to private SSH key.
        :param script_path: Path to a script to execute.
        :param output_path: The file system path to which script output is
          to be written.
        """
        self.host = host
        self.username = username
        self.private_key = private_key
        self.script_path = script_path
        self.output_path = output_path

    def run(self):
        """Executes the script against the remote host."""
        sshcmd = ('ssh -i {pkey} -o StrictHostKeyChecking=no {user}@{host} '
                'bash -s < {scriptpath} 2>&1 > {outpath}').format(
                    pkey=self.private_key,
                    user=self.username,
                    host=self.host,
                    scriptpath=self.script_path,
                    outpath=self.output_path)
        LOG.debug("ssh command: %s", sshcmd)
        LOG.info("executing script against %s@%s. this could take a few "
                 "minutes, follow progress in %s ...",
                 self.username, self.host, self.output_path)
        proc = subprocess.run(
            [sshcmd], shell=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        if proc.returncode != 0:
            LOG.error("script execution against %s@%s failed with exit "
                      "code %d (refer to log at %s for details)",
                      self.username, self.host, proc.returncode,
                      self.output_path)
        return proc.returncode
