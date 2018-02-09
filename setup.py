import os
from setuptools import setup, find_packages

root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)))
with open(os.path.join(root_dir, "VERSION"), 'r') as version_file:
    version = version_file.read().strip()

setup(
    name="hakube-installer",
    version=version,
    description="HA Kubernetes installer",
    author="Elastisys",
    author_email="techteam@elastisys.com",
    license="Apache Software License",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
    ],
    packages=find_packages(exclude=[]),
    include_package_data=True,
    install_requires=[
        "jinja2>=2.10,<3.0"
    ],
    entry_points={
        "console_scripts": [
            "hakube-installer = hakubeinstaller.main:cli"
        ],
    },
)
