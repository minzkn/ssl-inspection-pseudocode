#!/bin/sh

# BEGIN: toolchain 경로를 PATH환경변수에 맞춰주세요

export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.06/cn98xx-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.06/cn10ka-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.05/cn98xx-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.04/cn98xx-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.04/cn10ka-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.04-vpp2210/cn98xx-pcie-ep-release-output
#export OCTEON_SDK_BASE=/home/secui/work/build_octeon12.24.04-vpp2210/cn10ka-pcie-ep-release-output

export PATH=${OCTEON_SDK_BASE}/host/bin/:${PATH}

# END: toolchain 경로를 PATH환경변수에 맞춰주세요

make -j$(nproc) \
CROSS_COMPILE=aarch64-marvell-linux-gnu- \
${*}
