#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}
    make mrproper
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j8 all
    
fi

echo "Adding the Image to ${OUTDIR}"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p rootfs/{bin,dev,etc,home,lib,lib64,proc,sbin,sys,tmp,usr,var}
mkdir -p rootfs/usr/{bin,sbin,lib}
mkdir -p rootfs/var/log

echo "Base directories created in ${OUTDIR}/rootfs"


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make distclean
    make defconfig
else
    cd busybox
fi

# TODO: Make and install BUSYBOX
# Now build and install BusyBox
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX="${OUTDIR}/rootfs" ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Needed libraries"
${CROSS_COMPILE}readelf -a busybox | grep NEEDED

echo "Copy dependencies"
# TODO: Add library dependencies to rootfs
SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)

echo ${SYSROOT}

# Find required libraries and copy them
echo "Copying shared libraries from toolchain sysroot"
cp -a ${SYSROOT}/lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib 2>/dev/null || true
cp -a ${SYSROOT}/lib64/libc.so.6 ${OUTDIR}/rootfs/lib64 2>/dev/null || true
cp -a ${SYSROOT}/lib64/libm.so.6 ${OUTDIR}/rootfs/lib64 2>/dev/null || true
cp -a ${SYSROOT}/lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64 2>/dev/null || true

# You can check what exactly is needed via:
# ${CROSS_COMPILE}readelf -a busybox | grep NEEDED
#
#

# TODO: Make device nodes
cd ${OUTPUT_DIR}/rootfs
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/console c 5 1

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
mkdir -p "${OUTDIR}/rootfs/home/conf"
cp -r "${FINDER_APP_DIR}/../conf/"* "${OUTDIR}/rootfs/home/conf/"

cp "${FINDER_APP_DIR}/finder-test.sh" \
   "${FINDER_APP_DIR}/finder.sh" \
   "${OUTDIR}/rootfs/home"


#Correct 
sed -i 's|\.\./conf/|conf/|g' ${OUTDIR}/rootfs/home/finder-test.sh

# TODO: Clean and build the writer utility
cd ${FINDER_APP_DIR}
${CROSS_COMPILE}gcc -o writer writer.c
cp writer ${OUTDIR}/rootfs/home

# Ensure start-qemu-app.sh is copied into the rootfs /home directory
cp ${FINDER_APP_DIR}/start-qemu-app.sh ${OUTDIR}/rootfs/home

# Copy the autorun-qemu.sh script into the root filesystem /home directory
cp ${FINDER_APP_DIR}/autorun-qemu.sh ${OUTDIR}/rootfs/home

# TODO: Chown the root directory
sudo chown -R root:root ${OUTDIR}/rootfs

echo "Create initramfs.cpio.gz"
# TODO: Create initramfs.cpio.gz
cd ${OUTDIR}/rootfs
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio
