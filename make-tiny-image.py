#!/usr/bin/env python3
#
# Copyright (C) 2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import re
import sys
import glob
import argparse
import os
import os.path
import stat
import subprocess
from tempfile import TemporaryDirectory
from shutil import copy

def make_busybox(tmpdir, runcmd):
    bin = os.path.join(tmpdir, "bin")
    os.makedirs(bin, exist_ok=True)

    subprocess.check_call(["busybox", "--install", "-s", bin])
    shlink = os.path.join(tmpdir, "bin", "sh")
    busyboxin = os.readlink(shlink)
    busyboxout = os.path.join(tmpdir, busyboxin[1:])

    bbbin = os.path.dirname(busyboxout)
    os.makedirs(bbbin, exist_ok=True)
    if os.path.exists(busyboxout):
        os.unlink(busyboxout)
    copy(busyboxin, busyboxout)

    init = os.path.join(tmpdir, "init")
    with open(init, "w") as fh:
        print("""#!/bin/sh

mkdir /proc /sys
mount -t proc none /proc
mount -t sysfs none /sys

mount -n -t tmpfs none /dev
mknod -m 622 /dev/console c 5 1
mknod -m 666 /dev/null c 1 3
mknod -m 666 /dev/zero c 1 5
mknod -m 666 /dev/ptmx c 5 2
mknod -m 666 /dev/tty c 5 0
mknod -m 666 /dev/ttyS0 c 4 64
mknod -m 444 /dev/random c 1 8
mknod -m 444 /dev/urandom c 1 9

%s
poweroff -f
""" % runcmd, file=fh)
    os.chmod(init, stat.S_IRWXU)

def get_deps(binary):
    #if has_shbang(binary):
    #    return []
    out = subprocess.check_output(["ldd", binary]).decode("utf8")
    deps = []
    for line in out.split("\n"):
        m = re.search("=> (/[^ ]+)", line)
        if m is not None:
            deps.append(m.group(1))
        else:
            m = re.match("\s*(/[^ ]+)\s+\(.*\)\s*$", line)
            if m is not None:
                deps.append(m.group(1))
    return deps

def make_binaries(tmpdir, binaries):
    bindir = os.path.join(tmpdir, "bin")

    seen = {}
    libs = []
    for binary in binaries:
        if binary[0] == '/':
            src = binary
            dst = os.path.join(tmpdir, binary[1:])
        else:
            src = os.path.join("/usr/bin", binary)
            if not os.path.exists(src):
                src = os.path.join("/usr/sbin", binary)
            dst = os.path.join(bindir, binary)
        if os.path.exists(dst):
            os.unlink(dst)

        print("Copy bin %s -> %s" % (src, dst))
        copy(src, dst)

        libs.extend(get_deps(src))

    while len(libs):
        todo = libs
        libs = []
        for lib in todo:
            if lib in seen:
                continue

            dir = os.path.dirname(lib)
            libdir = os.path.join(tmpdir, dir[1:])
            os.makedirs(libdir, exist_ok=True)
            dst = os.path.join(tmpdir, lib[1:])
            copy(lib, dst)
            print("Copy lib %s -> %s"% (lib, dst))
            seen[lib] = True
            libs.extend(get_deps(lib))

def make_image(tmpdir, output, copyfiles, binaries, runcmd):
    make_busybox(tmpdir, runcmd)
    make_binaries(tmpdir, binaries)

    for copyfile in copyfiles:
        bits=copyfile.split("=")
        src = bits[0]
        dst = os.path.join(tmpdir, bits[1][1:])
        dstdir = os.path.dirname(dst)
        os.makedirs(dstdir, exist_ok=True)
        print("Copy extra %s -> %s" % (src, dst))
        copy(src, dst)

    files = glob.iglob(tmpdir + "/**", recursive=True)
    prefix=len(tmpdir) + 1
    files = [f[prefix:] for f in files]
    files = files[1:]
    filelist = "\n".join(files).encode("utf8")

    with open(output, "w") as fh:
        subprocess.run(["cpio", "--quiet", "-o", "-H", "newc"],
                       cwd=tmpdir, input=filelist, stdout=fh)

parser = argparse.ArgumentParser(description='Build a tiny initrd image')
parser.add_argument('--output', default="tiny-initrd.img",
                    help='Filename of output file')
parser.add_argument('--run', default="setsid cttyhack /bin/sh",
                    help='Command to execute in guest (default: "setsid cttyhack /bin/sh")')
parser.add_argument('--copy', action="append", default=[],
                    help='Extra files to copy  /src=/dst')
parser.add_argument('binary', nargs="*",
                    help='List of binaries to include')

args = parser.parse_args()

print (args.output)

with TemporaryDirectory(prefix="make-tiny-image") as tmpdir:
    make_image(tmpdir, args.output, args.copy, args.binary, args.run)
