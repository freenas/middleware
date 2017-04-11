import os, sys, errno
import time
import shutil
import bsd
from bsd.copy import copytree
import bsd.sysctl as sysctl
import bsd.dialog as Dialog
import bsd.geom as geom
import libzfs
import tempfile
import argparse

import freenasOS.Manifest as Manifest
import freenasOS.Package as Package
import freenasOS.Configuration as Configuration
import freenasOS.Installer as Installer

import Utils
from Utils import InitLog, LogIt, Project, Title, SetProject
from Utils import DiskInfo, SmartSize, RunCommand, RunCommandException
from Utils import Partition

zfs = libzfs.ZFS()

upgrade_paths = [
    "data",
    "conf/base/etc/hostid",
    "root/.ssh",
    "boot/modules",
    "usr/local/fusionio",
    "boot.config",
    "boot/loader.conf.local",
]

    
def InstallGrub(chroot, disks, bename, efi=False):
    # Tell beadm to activate the dataset, and make the grub
    # configuration.
    # To do that, we need to change some file.
    grub_files = ["{}/usr/local/sbin/beadm".format(chroot),
                  "{}/conf/base/etc/local/grub.d/10_ktrueos".format(chroot)]
    backup_data = {}
    for data_file in grub_files:
        LogIt("Backing up {}".format(data_file))
        with open(data_file, "r") as f:
            backup_data[data_file] = [x.rstrip() for x in f]
        with open(data_file, "w") as f:
            for line in backup_data[data_file]:
                if line.startswith("ROOTFS="):
                    LogIt("Setting {} -> {}".format(line, "ROOTFS={}".format(bename)))
                    print("ROOTFS={}".format(bename), file=f)
                else:
                    print(line, file=f)
    x = "{}/etc/local".format(chroot)
    if os.path.islink(x):
        # If /usr/local/etc is a symlink to /etc/local, we need to chagne it
        try:
            cleanit = os.readlink("{}/etc/local".format(chroot))
            LogIt("Getting rid of {}/etc/local".format(chroot))
            os.remove("{}/etc/local".format(chroot))
        except:
            cleanit = None
        try:
            os.symlink("/conf/base/etc/local", "{}/etc/local".format(chroot))
        except:
            pass
    else:
        cleanit = None

    os.environ["GRUB_TERMINAL_OUTPUT"] = "console serial"
    if efi:
        with open("{}/conf/base/etc/local/default/grub".format(chroot), "r") as f:
            lines = [x.rstrip() for x in f]
        with open("{}/conf/base/etc/local/default/grub".format(chroot), "w") as f:
            LogIt("Editing default/grub")
            for line in lines:
                LogIt("\t{}".format(line))
                if "GRUB_TERMINAL_OUTPUT=console" in line:
                    line = line.replace("GRUB_TERMINAL_OUTPUT=console", "GRUB_TERMINAL_OUTPUT=gfxterm")
                    LogIt("\t\t-> {}".format(line))
                print(line, file=f)
        
    for disk_name in disks:
        LogIt("InstallGrub:  disk={}".format(disk_name))
        disk = Utils.Disk(disk_name)
        if disk is None:
            LogIt("Cannot find disk info for {}".format(disk_name))
            raise InstallationError("Cannot find information for {}".format(disk_name))
        if efi:
            sysctl.sysctlbyname("kern.geom.debugflags", old=False, new=16)
            sysctl.sysctlbyname("kern.geom.label.disk_ident.enable", old=False, new=0)
            try:
                RunCommand("/sbin/glabel", "label", "efibsd", "/dev/{}p1".format(disk.name))
            except RunCommandException as e:
                LogIt("glabel got {}".format(str(e)))
                
            try:
                os.makedirs("{}/boot/efi".format(chroot), 0o755)
            except:
                pass
            LogIt("Attempting to mount /dev/{}p1 on {}/boot/efi".format(disk.name, chroot))
            bsd.nmount(source="/dev/{}p1".format(disk.name),
                       fspath="{}/boot/efi".format(chroot),
                       fstype="msdosfs")
            LogIt("Attempting to run grub-install in chrooted environment")
            RunCommand("/usr/local/sbin/grub-install",
                       "--efi-directory=/boot/efi",
                       "--removable",
                       "--target=x86_64-efi",
                       "/dev/{}".format(disk.name),
                       chroot=chroot)
            LogIt("Attempting to unmount {}/boot/efi".format(chroot))
            bsd.unmount("{}/boot/efi".format(chroot))
        else:
            RunCommand("/usr/local/sbin/grub-install",
                       "--modules=zfs part_gpt",
                       "/dev/{}".format(disk.name),
                       chroot=chroot)
    RunCommand("/usr/local/sbin/beadm", "activate",
               os.path.basename(bename),
               chroot=chroot)
    RunCommand("/usr/local/sbin/grub-mkconfig",
               "-o", "/boot/grub/grub.cfg",
               chroot=chroot)
    # Now put the grub files back to what they should be
    for name, data in backup_data.items():
        LogIt("Restoring {}".format(name))
        with open(name, "w") as f:
            for line in data:
                print(line, file=f)
                
    if cleanit:
        try:
            p = "{}/etc/local".format(chroot)
            os.remove(p)
            os.symlink(cleanit, p)
        except BaseException as e:
            LogIt("Got exception {} while trying to clean /etc/local fixup".format(str(e)))
            
class InstallationError(RuntimeError):
    def __init__(self, message=""):
        super(InstallationError, self).__init__(message)
        
def FormatDisks(disks, partitions, interactive):
    """
    Format the given disks.  Either returns a handle for the pool,
    or raises an exception.
    """
    # We don't care if these commands fail
    if interactive:
        status = Dialog.MessageBox(Title(),
                                   "Partitioning drive(s)",
                                   height=7, width=40, wait=False)
        status.clear()
        status.run()

    os_partition = None
    for part in partitions:
        if part.os is True:
            if os_partition is None:
                os_partition = part.index
            else:
                if os_partition != part.index:
                    if interactive:
                        Dialog.MessageBox("Partitioning Error",
                                          "Multiple partitions are claiming to be the OS partitions.  This must be due to a bug.  Aborting before any formatting is done",
                                          height=10, width=45).run()
                    raise InstallationError("Multiple OS partitions")
    # This could fail for a couple of reasons, but mostly we don't care.
    try:
        for disk in disks:
            RunCommand("/sbin/gpart", "destroy", "-F", disk.name)
    except:
        pass

    try:
        os_partition = None
        for disk in disks:
            RunCommand("/sbin/gpart", "create", "-s", "GPT", "-f", "active", disk.name)
            # For best purposes, the freebsd-boot partition-to-be
            # should be the last one in the list.
            for part in partitions:
                if part.os is True:
                    os_partition = part.index
                RunCommand("/sbin/gpart", "add",
                           "-t", part.type,
                           "-i", part.index,
                           "-s", part.smart_size,
                           disk.name)
                if part.type == "efi":
                    RunCommand("/sbin/newfs_msdos",
                               "-F", "16",
                               "/dev/{}p{}".format(disk.name, part.index))
                    
        geom.scan()
        if len(disks) > 1:
            vdev = libzfs.ZFSVdev(zfs, "mirror")
            components = []
            for disk in disks:
                tdev = libzfs.ZFSVdev(zfs, "disk")
                tdev.path = "/dev/{}p{}".format(disk.name, os_partition)
                components.append(tdev)
            vdev.children = components
        else:
            vdev = libzfs.ZFSVdev(zfs, "disk")
            vdev.path = "/dev/{}p{}".format(disks[0].name, os_partition)
                
        LogIt("Calling zfs.create, vdev = {}".format(vdev))
            
        try:
            freenas_boot = zfs.create("freenas-boot",
                                      topology={"data": [vdev]},
                                      opts={
                                          "cachefile" : "/tmp/zpool.cache",
                                          "version"   : "28",
                                      }, fsopts={
                                          "mountpoint" : "none",
                                          "atime"      : "off",
                                          "canmount"   : "off",
                                      })
        except:
            LogIt("Got exception while creating boot pool", exc_info=True)
            raise
        
        LogIt("Created freenas-boot")
        for feature in freenas_boot.features:
            if feature.name in ["async_destroy", "empty_bpobj", "lz4_compress"]:
                feature.enable()
                
        LogIt("Setting compression to lz4")
        freenas_boot.root_dataset.properties["compression"].value = "lz4"
        LogIt("Creating grub dataset")
        freenas_boot.create("freenas-boot/grub", { "mountpoint" : "legacy" })
        LogIt("Creating ROOT dataset")
        freenas_boot.create("freenas-boot/ROOT",  { "canmount" : "off" })
    except libzfs.ZFSException as e:
        LogIt("Got zfs exception {}".format(str(e)))
        if interactive:
            Dialog.MessageBox("Boot Pool Creation Failure",
                              "The {} Installer was unable to create the boot pool:\n\n\t{}".format(Project(), str(e)),
                              height=25, width=60).run()
            raise InstallationError("Unable to create boot pool")
    except RunCommandException as e:
        LogIt(str(e))
        if interactive:
            Dialog.MessageBox("Partitioning failure",
                              str("The {} Installer was unable to partition. The command:\n" +
                                  "\t{}\n" +
                                  "failed with the message:\n" +
                                  "\t{}").format(Project(), e.command, e.message),
                              height=25, width=60).run()
        raise InstallationError("Error during partitioning: \"{}\" returned \"{}\"".format(e.command, e.message))
    except Dialog.DialogEscape:
        raise
    except BaseException as e:
        LogIt("Got exception {} while partitioning".format(str(e)))
        if interactive:
            Dialog.MessageBox("Partitioning failure",
                              "The {} installer got an exception while partitioning:\n\n\t{}".format(Project(), str(e)),
                              height=25, width=60).run()
        raise InstallationError("Error during partitioning")

    return freenas_boot

def UnmountFilesystems(mountpoint):
    """
    This attempts to unmount all of the filesystems.
    Note that it unmounts /var
    """
    try:
        for directory in ["boot/grub", "dev", "var"]:
            try:
                path = os.path.join(mountpoint, directory)
                LogIt("Attempting to unmount {}".format(path))
                bsd.unmount(path)
            except BaseException as e:
                LogIt("Unable to unmount {}: {}".format(path, str(e)))
                raise
        try:
            bsd.unmount(mountpoint)
        except BaseException as e:
            LogIt("Unable to unmount BE: {}".format(str(e)))
            raise
        try:
            os.rmdir(mountpoint)
        except BaseException as e:
            LogIt("Could not remove {}: {}".format(mountpoint, str(e)))
    except:
        raise InstallationError("Unable to unmount filesystems in new Boot Environment")
    
def MountFilesystems(bename, mountpoint, **kwargs):
    """
    Mount the necessary filesystems, and clean up on error.
    The filesystems are bename -> mountpoint, freenas-boot/grub -> mountpoint/boot/grub,
    devfs -> mountpoint/dev, tmpfs mountpoint/var
    We also create mountpoint/boot/grub
    """
    mounted = []
    try:
        LogIt("Mounting {} on {}".format(bename, mountpoint))
        bsd.nmount(source=bename,
                   fspath=mountpoint,
                   fstype="zfs")
        mounted = [mountpoint]
        
        grub_path = "{}/boot/grub".format(mountpoint)
        LogIt("Mounting grub on {}".format(grub_path))
        os.makedirs(grub_path, 0o755)
        bsd.nmount(source="freenas-boot/grub",
                   fspath=grub_path,
                   fstype="zfs")
        mounted.append(grub_path)
        
        dev_path = os.path.join(mountpoint, "dev")
        LogIt("Mounting dev on {}".format(dev_path))
        os.makedirs(dev_path, 0o755)
        bsd.nmount(source="devfs",
                   fspath=dev_path,
                   fstype="devfs")
        mounted.append(dev_path)
        
    except os.error as e:
        LogIt("Got exception {} while mounting; have mounted {}".format(str(e), mounted))
        for path in mounted:
            try:
                bsd.unmount(path)
            except:
                raise InstallationError("Unable to mount filesystems")
    except BaseException as e:
        LogIt("Got base exception {}; have mounted {}".format(str(e), mounted))
        raise InstallationError("Error while mounting filesystems")

def RestoreConfiguration(**kwargs):
    upgrade_dir = kwargs.pop("save_path", None)
    interactive = kwargs.pop("interactive", False)
    dest_dir = kwargs.pop("destination", None)
    
    if interactive:
        try:
            status = Dialog.MessageBox(Title(),
                                       "Copying configuration files to new Boot Environment",
                                       height=7, width=60, wait=False)
            status.clear()
            status.run()
        except:
            pass
        try:
            for path in upgrade_paths:
                src = os.path.join(upgrade_dir, path)
                dst = os.path.join(dest_dir, path)
                if os.path.exists(src):
                    try:
                        os.makedirs(os.path.dirname(dst))
                    except:
                        pass
                    LogIt("Restoring {} -> {}".format(src, dst))
                    try:
                        copytree(src, dst,
                                 progress_callback=lambda s, d: LogIt("\t{} -> {}".format(s, d)))
                    except BaseException as e:
                        LogIt("Exception {}".format(str(e)))
                        raise InstallationError("Unable to restore configuration files for upgrade")
        finally:
            shutil.rmtree(upgrade_dir, ignore_errors=True)

def SaveConfiguration(**kwargs):
    interactive = kwargs.pop("interactive", False)
    upgrade_pool = kwargs.pop("pool", None)
    if interactive:
        status = Dialog.MessageBox(Title(),
                                   "Mounting boot pool for upgrade_pool",
                                   height=7, width=35, wait=False)
        status.clear()
        status.run()
    upgrade_dir = tempfile.mkdtemp()
    try:
        mount_point = tempfile.mkdtemp()
        zfs.import_pool(upgrade_pool,
                        "freenas-boot",
                        {})
        LogIt("Imported old freenas-boot")
        freenas_boot = zfs.get("freenas-boot")
        try:
            LogIt("Looking for bootable dataset")
            bootfs = freenas_boot.properties["bootfs"].value
            if bootfs is None:
                if interactive:
                    try:
                        Dialog.MessageBox(Title(),
                                          "No active boot environment for upgrade",
                                          height=7, width=35).run()
                    except:
                        pass
                raise InstallerError("No active boot environment for upgrade")
            
            LogIt("Found dataset {}".format(bootfs))
            bsd.nmount(source=bootfs,
                       fspath=mount_point,
                       fstype="zfs",
                       flags=bsd.MountFlags.RDONLY,
            )
            LogIt("Mounted pool")
            if interactive:
                status = Dialog.MessageBox(Title(),
                                           "Copying configuration files for update",
                                           height=7, width=36, wait=False)
                status.clear()
                status.run()
            try:
                # Copy files now.
                for path in upgrade_paths:
                    src = os.path.join(mount_point, path)
                    dst = os.path.join(upgrade_dir, path)
                    if os.path.exists(src):
                        try:
                            os.makedirs(os.path.dirname(dst))
                        except:
                            pass
                        LogIt("Copying {} -> {}".format(src, dst))
                        copytree(src, dst,
                                 progress_callback=lambda s, d: LogIt("\t{} -> {}".format(s, d)))
                return upgrade_dir
            except BaseException as e:
                LogIt("While copying, got exception {}".format(str(e)))
                raise
            finally:
                LogIt("Unmounting pool")
                bsd.unmount(mount_point)

        except BaseException as e:
            LogIt("But got an excetion {}".format(str(e)))
        finally:
            LogIt("Exporting old freenas-boot pool")
            zfs.export_pool(freenas_boot)
    except InstallationError:
        raise
    except:
        if interactive:
            Dialog.MessageBox(Title(),
                              "Saving configuration files for upgrade_pool has failed",
                              height=10, width=45).run()
        raise
    finally:
        try:
            os.rmdir(mount_point)
        except:
            pass
        
def Install(**kwargs):
    """
    This does the grunt-work of actually doing the install.
    The possible arguments are:
    - config	Object containing configuration.  This is where the download URL and
            	package directories will be specified.
    - interactive	Whether or not to be interactive.  If true (default), then
		bsd.Dialog will be used to for status and error messages.
    - disks	An array of Disk objects to install to.  If set, then the disks
    		will be partitioned and erased.  If NOT set, then the installer
		will create a new boot environment on the existing freenas-boot pool.
    - efi	Boolean indicating whether or not to use EFI (default is False).
    - upgrade_from	An unimported ZFSPool object to install to.  This must be set
    			when upgrading, and when creating a new BE on an existing pool.
    - upgrade	Boolean indicating whether or not to upgrade.  Requires upgrade_from to
		be valid.
    - password	A string indicating the root password.  Ignored for upgrades; may be None
    		(indicating no password, not recommended).
    - partitions	An array of Partition objects (see Utils).  Note that the OS
    			partition will always be installed last.
    - package_handler	Call-back for the start of each package.  Arguments are
			(index [int], name [string], packages [array of package names])
    			be installed.
    - progress_handler	Call-back after each file/directory is installed.  Arguments are **kwargs,
    			will [currently] be either done=True (indicating the package is installed),
    			or (total=int [number of objects], index=int [current index], name=string
    			[name of object that was just installed]).
    - manifest	A manifest object.  Must be set.
    - package_directory	A path where the package files are located.  The package files must
    			already be located in this directory.
    - trampoline	A boolean indicating whether the post-install scripts should be run
    			on reboot (True, default) or during the install (False).
    """
    LogIt("Install({})".format(kwargs))
    orig_kwargs = kwargs.copy()

    config = kwargs.pop("config", Configuration.SystemConfiguration())
    interactive = kwargs.pop("interactive", True)
    disks = kwargs.pop("disks", [])
    efi = kwargs.pop("efi", False)
    upgrade_pool = kwargs.pop("upgrade_from", None)
    upgrade = kwargs.pop("upgrade", False)
    password = kwargs.pop("password", None)
    extra_partitions = kwargs.pop("partitions", None)
    package_notifier = kwargs.pop("package_handler", None)
    progress_notifier = kwargs.pop("progress_handler", None)
    manifest = kwargs.pop("manifest", None)
    trampoline = kwargs.pop("trampoline", True)
    # The default is based on ISO layout
    package_dir = kwargs.pop("package_directory", "/.mount/{}/Packages".format(Project()))

    if not manifest:
        if interactive:
            try:
                Dialog.MessageBox(Title(),
                                  "No manifest specified for the installation",
                                  height=7, width=45).run()
            except:
                pass
        raise InstallationError("No manifest specified for the installation")
                    
    config.SetPackageDir(package_dir)
    
    mount_point = tempfile.mkdtemp()
    
    # Quick sanity check
    if upgrade and upgrade_pool is None:
        if interactive:
            Dialog.MessageBox(Title(), "\nNo pool to upgrade from",
                              height=7, width=30).run()
        raise InstallationError("Upgrade selected but not previous boot pool selected")

    if disks is None and upgrade_pool is None:
        if interactive:
            Dialog.MessageBox(Title(), "\nNo disks or previous pool selected",
                              height=10, width=30).run()
        raise InstallationError("No disks or previous boot pool selected")
    
    # First step is to see if we're upgrading.
    # If so, we want to copy files from the active BE to
    # a location in /tmp, so we can copy them back later.
    # This will import, and then export, the freenas-boot pool.
    
    if upgrade_pool and upgrade:
        upgrade_dir = SaveConfiguration(interactive=interactive,
                                        pool=upgrade_pool)
    else:
        upgrade_dir = None

    # Second step is to see if we're formatting drives.
    # If so, we first will destroy the freenas-boot pool;
    # after that, we will partition the drives.  How we partition
    # depends on the boot method -- efi or bios.  We set the
    # BE name to "default" and create the freenas-boot pool, and
    # then the grub dataset.
    #
    # If we're NOT formatting the drive, we set the pool name
    # to time.strftime("default-%Y%m%d-%H%M%S")
    
    LogIt("disks = {}".format(disks))
    if disks:
        # This means we're formatting
        # We need to know what size and types to make the partitions.
        # If we're using EFI, then we need a 100mbyte msdosfs partition;
        # otherwise a 512k bios-boot.  If we have any extra partitions,
        # we'll take those into account as well.  For the big freebsd-zfs
        # partition, we'll take the minimum of the remaining space,
        # rounded down to the nearest gbyte.
        gByte = 1024 * 1024 * 1024
        if efi:
            # 100mbytes for efi partition
            used = 100 * 1024 * 1024
            boot_part = Partition(type="efi",
                                  index=1,
                                  size=used)
        else:
            # BIOS partition gets 512kbytes
            used = 512 * 1024
            boot_part = Partition(type="bios-boot",
                                  index=1,
                                  size=used)
        partitions = [boot_part]

        # For now, we always make the freenas-boot partition index 2, and place
        # it at the end of the disk.
        next_index = 3
        for part in (extra_partitions or []):
            # We will ignore the index given here.
            part.index = next_index
            used += part.size
            LogIt("Additional partition {}".format(part))
            partitions.append(part)
            next_index += 1

        # At this point, used is the sum of the partitions, in bytes.
        # This isn't really correct - we should be rounding the size up
        # to the blocksize of the disk.  But partitioning behaves strangely
        # sometimes with flash drives.  As a result, when we do the actual
        # partitioning, we use the smart-size (e.g., 1G), which rounds down.
        
        min_size = 0
        for disk in disks:
            # If the remaining space is too small, this installation won't work well.
            size = disk.size
            size = size - used
            if size < gByte:
                if size < 0:
                    fspace = "no free space after the other partitions"
                else:
                    fspace = "free space is {}, minimum is 1Gbyte".format(SmartSize(size))
                name = disk.name
                LogIt("Disk {} is too small {}".format(name, fspace))
                ssize = SmartSize(disk.size)
                if interactive:
                    Dialog.MessageBox(Title(),
                                      "Disk {} is too small ({})".format(name, ssize),
                                      height=10, width=25).run()
                raise InstallationException("Disk {} is too small ({})".format(name, ssize))
            if (size < min_size) or (not min_size):
                min_size = size
        if min_size == 0:
            if interactive:
                Dialog.MessageBox(Title(),
                                  "Unable to find the size of any of the selected disks",
                                  height=15, weidth=60).run()
            raise InstallationError("Unable to find disk size")
        
        # Round min_size down to a gbyte
        part_size = int(min_size / gByte) * gByte
        os_part = Partition(type="freebsd-zfs",
                            index=2,
                            size=part_size,
                            os=True)
        LogIt("OS partition {}".format(os_part))
        partitions.append(os_part)
                
        # We need to destroy any existing freenas-boot pool.
        # To do that, we may first need to import the pool.
        if upgrade_pool is None:
            try:
                old_pools = list(zfs.find_import(name="freenas-boot"))
            except libzfs.ZFSException as e:
                LogIt("Got ZFS error {} while trying to import freenas-boot for destruction".format(str(e)))
                old_pools = []
        else:
            old_pools = [upgrade_pool]
            # We'll be destroying it, so..
            upgrade_pool = None

        for pool in old_pools:
            try:
                dead_pool = zfs.import_pool(pool, "freenas-boot", {})
                if dead_pool is None:
                    dead_pool = zfs.get("freenas-boot")
                zfs.destroy("freenas-boot")
            except libzfs.ZFSException as e:
                LogIt("Trying to destroy a freenas-boot pool got error {}".format(str(e)))
            
        try:
            freenas_boot = FormatDisks(disks, partitions, interactive)
        except BaseException as e:
            LogIt("FormatDisks got exception {}".format(str(e)))
            raise
        
        bename = "freenas-boot/ROOT/default"
    else:
        # We need to import the pool (we exported it above if upgrade_pool)
        try:
            if upgrade_pool:
                freenas_boot = zfs.import_pool(upgrade_pool, "freenas-boot", {})
            else:
                freenas_boot = None
                pools = list(zfs.find_import(name="freenas-boot"))
                if len(pools) > 1:
                    raise InstallationError("There are multiple unimported freenas-boot pools")
                if len(pools) == 1:
                    freenas_boot = zfs.import_pool(upgrade_pool, "freenas-boot", {})
            if freenas_boot is None:
                freenas_boot = zfs.get("freenas-boot")
        except libzfs.ZFSException as e:
            LogIt("Got ZFS error {} while trying to import pool".format(str(e)))
            if interactive:
                Dialog.MessageBox("Error importing boot pool",
                                  "The {} Installer was unable to import the boot pool:\n\n\t{}".format(Project(), str(e)),
                                  height=25, width=60).run()
            raise InstallationError("Unable to import boot pool")

        bename = time.strftime("freenas-boot/ROOT/default-%Y%m%d-%H%M%S")
        
    # Next, we create the dataset, and mount it, and then mount
    # the grub dataset.
    # We also mount a devfs and tmpfs in the new environment.

    LogIt("BE name is {}".format(bename))
    try:
        freenas_boot.create(bename, fsopts={
            "mountpoint" : "legacy",
            "sync"       : "disabled",
        })
    except libzfs.ZFSException as e:
        LogIt("Could not create BE {}: {}".format(bename, str(e)))
        if interactive:
            Dialog.MessageBox(Title(),
                              "An error occurred creatint the installation boot environment\n" +
                              "\n\t{}".format(str(e)),
                              height=25, width=60).run()
        raise InstallationError("Could not create BE {}: {}".format(bename, str(e)))
    
    MountFilesystems(bename, mount_point)
    # After this, any exceptions need to have the filesystems unmounted
    try:
        # If upgrading, copy the stashed files back
        if upgrade_dir:
            RestoreConfiguration(save_path=upgrade_dir,
                                 interactive=interactive,
                                 destination=mount_point)
        else:
            # It turns out the install won't work at all if /data/freenas.db isn't
            # there.  It can be empty, and is on the ISO.
            if os.path.exists("/data"):
                try:
                    copytree("/data", "{}/data".format(mount_point))
                except:
                    pass
            if not os.path.exists("{}/data/freenas.db".format(mount_point)):
                os.makedirs("{}/data/freenas.db".format(mount_point), 0o755)
            # We should also handle some FN9 stuff
            # In this case, we want the newer database file, for migration purposes
            if os.path.exists("/data/freenas-v1.db"):
                copytree("/data/freenas-v1.db", "{}/data/freenas-v1.db".format(mount_point))
                    
        # After that, we do the installlation.
        # This involves mounting the new BE,
        # and then running the install code on it.

        installer = Installer.Installer(manifest=manifest,
                                        root=mount_point,
                                        config=config)

        if installer.GetPackages() is not True:
            LogIt("Installer.GetPackages() failed")
            raise InstallationError("Unable to load packages")
        
        # This should only be true for the ISO installer.
        installer.trampoline = trampoline
        
        start_time = time.time()
        try:
            installer.InstallPackages(progressFunc=progress_notifier,
                                      handler=package_notifier)
        except BaseException as e:
            LogIt("InstallPackaages got exception {}".format(str(e)))
            raise InstallationError("Could not install packages")
        # Packages installed!
        if interactive:
            try:
                status = Dialog.MessageBox(Title(), "Preparing new boot environment",
                                           height=5, width=35, wait=False)
                status.clear()
                status.run()
            except:
                pass
        for f in ["{}/conf/default/etc/fstab".format(mount_point),
                  "{}/conf/base/etc/fstab".format(mount_point)
                  ]:
            try:
                os.remove(f)
            except:
                LogIt("Unable to remove {} -- ignoring".format(f))
                    
        try:
            with open("{}/etc/fstab".format(mount_point), "w") as fstab:
                print("freenas-boot/grub\t/boot/grub\tzfs\trw,noatime\t1\t0", file=fstab)
        except OSError as e:
            LogIt("Unable to create fstab: {}".format(str(e)))
            raise InstallationError("Unable to create filesystem table")
        try:
            os.link("{}/etc/fstab".format(mount_point),
                    "{}/conf/base/etc/fstab".format(mount_point))
        except OSError as e:
            LogIt("Unable to link /etc/fstab to /conf/base/etc/fstab: {}".format(str(e)))
            
        # Here, I should change module_path in boot/loader.conf, and get rid of the kernel line
        try:
            lines = []
            boot_config = "{}/boot/loader.conf".format(mount_point)
            with open(boot_config, "r") as bootfile:
                for line in bootfile:
                    line = line.rstrip()
                    if line.startswith("module_path="):
                        lines.append('module_path="/boot/kernel;/boot/modules;/usr/local/modules"')
                    elif line.startswith("kernel="):
                        lines.append('kernel="kernel"')
                    else:
                        lines.append(line)
            with open(boot_config, "w") as bootfile:
                for line in lines:
                    print(line, file=bootfile)
        except BaseException as e:
            LogIt("While modifying loader.conf, got exception {}".format(str(e)))
            # Otherwise I'll ignore it, I think
                        
        # This is to support Xen
        try:
            hvm = RunCommand("/usr/local/sbin/dmidecode", "-s", "system-product-name",
                             chroot=mount_point)
            if hvm == "HVM domU":
                with open(os.path.join(mount_point, "boot", "loader.conf.local"), "a") as f:
                    print('hint.hpet.0.clock="0"', file=f)
        except BaseException as e:
            LogIt("Got an exception trying to set XEN boot loader hint: {}".format(str(e)))
            
        # Now I have to mount a tmpfs on var
        try:
            LogIt("Mounting tmpfs on var")
            bsd.nmount(source="tmpfs",
                       fspath=os.path.join(mount_point, "var"),
                       fstype="tmpfs")
        except BaseException as e:
            LogIt("Got exception {} while trying to mount {}/var: {}".format(mount_point, str(e)))
            raise InstallationError("Unable to mount temporary space in newly-created BE")
        # Now we need to populate a data structure
        mtree_command = ["/usr/sbin/mtree", "-deUf" ]
        if os.path.exists("/usr/sbin/mtree"):
            mtree_command.append("{}/etc/mtree/BSD.var.dist".format(mount_point))
            mtree_command.extend(["-p", "{}/var".format(mount_point)])
            chroot=None
        else:
            mtree_command.extend(["/etc/mtree/BSD.var.dist", "-p", "/var"])
            chroot=mount_point

        try:
            RunCommand(*mtree_command,
                       chroot=chroot)
        except RunCommandException as e:
            LogIt("{} (chroot={}) failed: {}".format(mtree_command, chroot, str(e)))
            raise InstallationError("Unable to prepare new boot environment")

        # This part is FN10-specific
        # Now to start dsinit and mongoDB
        try:
            RunCommand("/etc/rc.d/ldconfig", "start",
                       chroot=mount_point)
            RunCommand("/usr/local/sbin/dsinit", "--start-forked",
                       chroot=mount_point)
        except RunCommandException as e:
            LogIt("{} failed: {}".format(e.command, str(e)))
            raise InstallationError("Unable to start {} configuration: {}".format(Project(), e.message))
    
        try:
            # We need to put this in a try block so we can stop dsinit,
            # otherwise we can't unmount the filesystems

            if interactive:
                try:
                    status = Dialog.MessageBox(Title(),
                                               "Initializing database configuration",
                                               height=7, width=40, wait=False)
                    status.clear()
                    status.run()
                except:
                    pass

            if not os.path.exists("{}/data/freenas.db/freenas"):
                RunCommand("/usr/local/sbin/dsrestore",
                           "-t", "persistent,config",
                           "-f", "/usr/local/share/datastore/factory.json",
                           chroot=mount_point)
            RunCommand("/usr/local/sbin/dsmigrate",
                       "-t", "persistent,config",
                       "-f", "/usr/local/share/datastore/factory.json",
                       "-d", "/usr/local/share/datastore/migrations",
                       chroot=mount_point)

            # Now we need to install grub
            # We do this even if we didn't format the disks.
            # But if we didn't format the disks, we need to use the same type
            # of boot loader.
            if interactive:
                try:
                    status = Dialog.MessageBox(Title(), "Installing boot loader",
                                               height=5, width=35, wait=False)
                    status.clear()
                    status.run()
                except:
                    pass
            # We've just repartitioned, so rescan geom
            geom.scan()
            # Set the boot dataset
            freenas_boot.properties["bootfs"].value = bename
            LogIt("Set bootfs to {}".format(bename))
            # This is EXTREMELY ANNOYING.
            # I'd like to use libzfs to set the property here, but
            # I have to do it in the chrooted environment, because otherwise
            # zfs returns an error and doesn't set it.
            #freenas_boot.properties["cachefile"].value = "/boot/zfs/rpool.cache"
            try:
                RunCommand("/sbin/zpool",
                           "set", "cachefile=/boot/zfs/rpool.cache",
                           "freenas-boot",
                           chroot=mount_point)
            except RunCommandException as e:
                LogIt("Got exception {} while trying to set cachefile".format(str(e)))
                raise InstallationException("Could not set cachefile on boot pool")
            LogIt("Set cachefile to /boot/zfs/rpool.cache")
            try:
                use_efi = Utils.BootPartitionType(freenas_boot.disks[0]) == "efi"
                InstallGrub(chroot=mount_point,
                            disks=freenas_boot.disks,
                            bename=bename, efi=use_efi)
            except RunCommandException as e:
                LogIt("Command {} failed: {} (code {})".format(e.command, e.message, e.code))
                raise InstallationError("Boot loader installation failure")
            except BaseException as e:
                LogIt("InstallGrub got exception {}".format(str(e)))
                raise
    
            if interactive:
                try:
                    status = Dialog.MessageBox(Title(), "Finalizing installation",
                                               height=5, width=35, wait=False)
                    status.clear()
                    status.run()
                except BaseException as e:
                    LogIt("Finalizing got exception {}".format(str(e)))
                    
            if not upgrade and password is not None:
                if interactive:
                    try:
                        status = Dialog.MessageBox(Title(), "\nSetting root password",
                                                   height=7, width=35, wait=False)
                        status.clear()
                        status.run()
                    except:
                        pass
                try:
                    RunCommand("/usr/local/sbin/dspasswd", "root", password,
                               chroot=mount_point)
                except RunCommandException as e:
                    LogIt("Setting root password: {}".format(str(e)))
                    raise InstallationError("Unable to set root password")
        except BaseException as e:
            LogIt("Got exception {} during configuration".format(str(e)))
            if interactive:
                try:
                    Dialog.MessageBox(Title(),
                                      "Error during configuration",
                                      height=7, width=35).run()
                except:
                    pass
            raise
        finally:
            try:
                RunCommand("/usr/local/sbin/dsinit", "--stop-forked", chroot=mount_point)
            except BaseException as e:
                LogIt("Got {} while trying to stop dsinit".format(str(e)))

        # Let's turn sync back to default for the dataset
        try:
            ds = zfs.get_dataset(bename)
        except libzfs.ZFSException as e:
            LogIt("Got ZFS error {} while trying to get {} dataset".format(str(e), bename))
            raise InstallationError("Could not fid newly-created BE {}".format(bename))
        try:
            ds.properties["sync"].inherit()
        except BaseException as e:
            LogIt("Unable to set sync on {} to inherit: {}".format(bename, str(e)))
            # That's all I'm going to do for now

        # We save the manifest
        manifest.Save(mount_point)
        # And we're done!
        end_time = time.time()
    except InstallationError as e:
        # This is the outer try block -- it needs to ensure mountpoints are
        # cleaned up
        LogIt("Outer block got error {}".format(str(e)))
        if interactive:
            try:
                Dialog.MessageBox("{} Installation Error".format(Project()),
                                  e.message,
                                  height=25, width=50).run()
            except:
                pass
        raise
    except BaseException as e:
        LogIt("Outer block got base exception {}".format(str(e)))
        raise
    finally:
        if package_dir is None:
            LogIt("Removing downloaded packages directory {}".format(cache_dir))
            shutil.rmtree(cache_dir, ignore_errors=True)
        UnmountFilesystems(mount_point)

    LogIt("Exporting freenas-boot at end of installation")
    try:
        zfs.export_pool(freenas_boot)
    except libzfs.ZFSException as e:
        LogIt("Could not export freenas boot: {}".format(str(e)))
        raise

    if interactive:
        total_time = int(end_time - start_time)
        Dialog.MessageBox(Title(),
                          "The {} installer has finished the installation in {} seconds".format(Project(), total_time),
                          height=8, width=40).run()
        
        

    
