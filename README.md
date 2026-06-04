# tcp-wg kernel module

Out-of-tree Linux kernel module for the `tcp-wg` network link type.

This README documents one supported installation flow:

1. clone this repository,
2. build the kernel module,
3. install it with the Makefile.

## Table of contents

- [Installation](#installation)
  - [Requirements](#requirements)
  - [Build and install](#build-and-install)
  - [Verify the installation](#verify-the-installation)
  - [Upgrade or reinstall](#upgrade-or-reinstall)
  - [Uninstall](#uninstall)
- [Makefile reference](#makefile-reference)
  - [Targets](#targets)
  - [Variables](#variables)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Installation

### Requirements

Install the build toolchain, the headers for the kernel you are building
against, and DKMS. The default `make install` target uses DKMS.

Debian or Ubuntu:

```shell
sudo apt update
sudo apt install -y git build-essential dkms linux-headers-amd64
```

On Debian or Ubuntu cloud kernels, prefer the cloud header meta package:

```shell
sudo apt install -y git build-essential dkms linux-headers-cloud-amd64
```

Prefer `linux-headers-amd64` or `linux-headers-cloud-amd64` when they match
your kernel flavour. These meta packages track kernel upgrades and keep matching
headers installed for future DKMS rebuilds. Use `linux-headers-$(uname -r)` only
when you need the exact headers for the currently running kernel and the
appropriate meta package is not available for that system.

RHEL, CentOS Stream, Fedora, or compatible distributions:

```shell
sudo dnf install -y git make gcc dkms kernel-devel-$(uname -r)
```

Arch Linux:

```shell
sudo pacman -S --needed git base-devel dkms linux-headers
```

The kernel build directory must exist. By default the Makefile uses:

```shell
/lib/modules/$(uname -r)/build
```

Check it before building:

```shell
test -d /lib/modules/$(uname -r)/build
```

If this command fails, install the matching kernel headers or kernel-devel
package for the kernel reported by `uname -r`.

### Build and install

Clone the repository, enter the module source directory, build it, and install
it:

```shell
git clone https://github.com/sudogeeker/tcpwg-linux-kernel-module.git
cd tcpwg-linux-kernel-module/src
make -j"$(nproc)"
sudo make install
```

`make` builds `tcp-wg.ko` for the currently running kernel.

`sudo make install` is the canonical install command. In this Makefile,
`install` is an alias for `dkms-install`. It copies the source into
`/usr/src/tcp-wg-1.0.0`, registers the module with DKMS if needed, rebuilds it
for the selected kernel, installs it, and runs `depmod`.

The DKMS install path is used because it can rebuild the module when the kernel
changes.

### Verify the installation

Load the module:

```shell
sudo modprobe tcp-wg
```

Check that the installed module is visible to the kernel:

```shell
modinfo tcp-wg
```

Check that the link type is registered:

```shell
sudo ip link add dev wg-test type tcp-wg
sudo ip link delete dev wg-test
```

If `ip link add` fails with an unknown device type, the module is not loaded or
was not installed for the running kernel.

### Upgrade or reinstall

Pull the latest source and run the same build/install flow again:

```shell
cd tcpwg-linux-kernel-module
git pull --ff-only
cd src
make clean
make -j"$(nproc)"
sudo make install
```

The `dkms-install` target removes an already built or installed DKMS entry for
the selected kernel before rebuilding it, so reinstalling the same version is
supported.

After reinstalling, reload the module if it is already loaded:

```shell
sudo modprobe -r tcp-wg
sudo modprobe tcp-wg
```

If an interface is using the module, delete or stop that interface before
running `modprobe -r`.

### Uninstall

There is no Makefile uninstall target. For a DKMS install, remove the DKMS
module version directly:

```shell
sudo dkms remove -m tcp-wg -v 1.0.0 --all
```

Then remove any remaining installed module file for kernels where it exists and
refresh module dependencies:

```shell
sudo find /lib/modules -name 'tcp-wg.ko*' -delete
sudo depmod -a
```

## Makefile reference

All commands in this section are run from the `src` directory:

```shell
cd tcpwg-linux-kernel-module/src
```

### Targets

- `make`, `make all`, or `make module`
  Builds `tcp-wg.ko` through the kernel build system:

  ```shell
  make -C $(KERNELDIR) M=$(PWD) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules
  ```

- `make debug`
  Builds the module with verbose kernel build output and `CONFIG_TCP_WG_DEBUG=y`.
  This enables the debug-specific flags from `Kbuild`.

- `make clean`
  Runs the kernel build system clean target for this external module.

- `sudo make module-install`
  Runs `modules_install` for the selected kernel and then `depmod`. This is a
  direct current-kernel install target from the Makefile; it does not use DKMS
  and does not automatically rebuild after a kernel upgrade. It is documented
  here as a Makefile target, not as the supported installation flow.

- `sudo make install`
  Alias for `dkms-install`. This is the supported installation target.

- `sudo make dkms-install`
  Runs `dkms-source-install`, verifies that the `dkms` command exists, adds the
  module to DKMS when needed, removes any already built or installed entry for
  the selected kernel, rebuilds, installs with `--force`, and runs `depmod`.

- `sudo make dkms-source-install`
  Copies the source files used by DKMS into `$(DESTDIR)$(DKMSDIR)` and rewrites
  `PACKAGE_VERSION` in the copied `dkms.conf`. Tests and generated
  `*.mod.c` files are intentionally excluded. This target is useful for
  packaging. It does not build or install the module by itself.

- `make style`
  Runs the kernel `checkpatch.pl` script against the module sources.

- `make check`
  Runs `scan-build` with extra sparse/endian checking flags. This requires
  `scan-build` to be installed.

- `make coccicheck`
  Runs the kernel `coccicheck` target in report mode.

- `make cloc`
  Counts source lines with `cloc`, filtering compat definitions through the
  helper script under `kernel-tree-scripts/`.

### Variables

The Makefile supports the following variables. Pass them on the command line
when needed, for example `make KERNELRELEASE=6.12.0-custom`.

- `WIREGUARD_VERSION`
  Version string compiled into the module. Default: `1.0.0`.

- `OMIT_ENDPOINTS`
  When set, passes `OMIT_ENDPOINTS` into Kbuild. Default: empty.

- `KERNELRELEASE`
  Kernel release to build or install for. Default: `$(uname -r)`.

- `KERNELDIR`
  Kernel build directory used by `module`, `module-debug`, `clean`, and
  `module-install`. Default: `/lib/modules/$(KERNELRELEASE)/build`.

- `PREFIX`
  Base prefix for source installation paths. Default: `/usr`.

- `DESTDIR`
  Packaging destination root. Used by `dkms-source-install`. `dkms-install`
  refuses to run when `DESTDIR` is set.

- `SRCDIR`
  Source directory under `PREFIX`. Default: `$(PREFIX)/src`.

- `DKMS`
  DKMS executable name or path. Default: `dkms`.

- `DKMS_NAME`
  DKMS module name. Default: `tcp-wg`.

- `DKMS_VERSION`
  DKMS module version. Default: `$(WIREGUARD_VERSION)`.

- `DKMSDIR`
  Destination used by `dkms-source-install`. Default:
  `$(SRCDIR)/$(DKMS_NAME)-$(DKMS_VERSION)`, which expands to
  `/usr/src/tcp-wg-1.0.0` with default values.

- `DEPMOD`
  `depmod` executable name or path. Default: `depmod`.

- `DEPMODBASEDIR`
  Base directory passed to `depmod -b`. Default: `/`.

## Configuration

> [!IMPORTANT]
> All parameters must be the same between client and server, except for Jc,
> Jmin, and Jmax. Those three may vary.

- Jc: `1 <= Jc <= 128`; recommended range is 4 to 12 inclusive.
- Jmin: `Jmax > Jmin < 1280`; recommended value is 8.
- Jmax: `Jmin < Jmax <= 1280`; recommended value is 80.
- S1: `S1 <= 1132` when assuming an MTU of 1280; `S1 + 56 != S2`;
  recommended range is 15 to 150 inclusive.
- S2: `S2 <= 1188` when assuming an MTU of 1280; recommended range is 15 to
  150 inclusive.
- H1/H2/H3/H4: must be unique among each other; recommended range is 5 to
  2147483647 inclusive.

The MTU-derived values above assume a basic internet connection with an MTU of
1280.

## Troubleshooting

### Missing kernel headers

If the build fails because the kernel build directory cannot be found, install
headers for the exact kernel returned by:

```shell
uname -r
```

Then verify:

```shell
test -d /lib/modules/$(uname -r)/build
```

### DKMS is not installed

`sudo make install` requires DKMS. If DKMS is unavailable, install it with your
distribution package manager and run `sudo make install` again.

### Secure Boot blocks module loading

On Secure Boot systems, unsigned out-of-tree kernel modules may fail to load.
Check the kernel log:

```shell
dmesg -T | grep -i 'tcp-wg\|module\|lockdown\|signature'
```

Either sign the DKMS-built module according to your distribution's Secure Boot
workflow or disable Secure Boot for testing.

### Module is installed but not loaded

Load it manually and inspect the kernel log:

```shell
sudo modprobe tcp-wg
dmesg -T | tail -100
```

### Enable debug logging

To get more details, enable dynamic debug for the module:

```shell
echo "module tcp-wg +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

Watch logs live with:

```shell
dmesg -wT
```

### Stale DKMS state

If DKMS reports a stale or broken build for this module, remove the version and
install again:

```shell
sudo dkms remove -m tcp-wg -v 1.0.0 --all
sudo make install
```

## License

This project is released under the [GPLv2](COPYING).
