#!/bin/bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential mtools libssl-dev pkg-config
sudo apt-get install -yq flex bison libelf-dev qemu-utils qemu-system libglib2.0-dev libpixman-1-dev libseccomp-dev socat
nohup curl https://sh.rustup.rs -sSf | sh -s -- -y
scripts/run_unit_tests.sh
scripts/run_integration_tests.sh
