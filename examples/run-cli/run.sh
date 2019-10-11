#!/bin/bash

KERNEL="/opt/kata/share/kata-containers/vmlinux-virtiofs.container"
IMAGE="/home/ubuntu/workloads/clear-cloudguest-raw.img"
SOCKET=/tmp/ch.sock
rm -rf "${SOCKET}"
echo "export API_SOCKET=${SOCKET}" >> socket-init-ch.sh

cargo run --bin cloud-hypervisor -- \
	--api-socket "${SOCKET}" \
	--console off \
	--serial tty \
	--kernel "${KERNEL}" \
	--disk path="${IMAGE}" \
	--cmdline "console=ttyS0 reboot=k panic=1 nomodules i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda2 init=/bin/bash" \
	--cpus 4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
	--rng
