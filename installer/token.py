import random
import re

class ClusterToken:
    """A random cluster token of form `99akrf.aod7xt6dctnqe4ej`."""
    def __init__(self, token=None):
        if token:
            self.token = token
        else:
            self.token = self._generate()

    def get(self):
        return self.token

    def _generate(self):
        alphanum_chars = '0123456789abcdefghijklmnopqrstuvwxyz'
        part1 = []
        for i in range(0,6):
            part1.append(random.choice(alphanum_chars))
        part2 = []
        for i in range(0,16):
            part2.append(random.choice(alphanum_chars))
        return "{}.{}".format("".join(part1), "".join(part2))



    @staticmethod
    def parse(filepath):
        """Parses a `ClusterToken` from a file, raises an Exception on
        failure."""
        with open(filepath, "r") as f:
            token = f.read().strip()
            if not re.fullmatch('[0-9a-z]{6}\.[0-9a-z]{16}', token):
                raise ValueError("{} does not contain a valid cluster token".format(filepath))
            return ClusterToken(token)
