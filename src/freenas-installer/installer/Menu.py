import os, sys
import subprocess
import time
import argparse
import bsd
import bsd.dialog as Dialog
import bsd.geom as geom
from bsd.sysctl import sysctlbyname
import libzfs

import freenasOS.Manifest as Manifest
import freenasOS.Configuration as Configuration

import Install
from Install import InstallationError

import Utils
from Utils import InitLog, LogIt, Title, Project, SetProject
from Utils import BootMethod, DiskRealName, SmartSize, RunCommand

zfs = libzfs.ZFS()

# This is used to get progress information.  This assumes
# interactive; other callers of Install() will need to provide
# their own.  Note the ProgressHandler class in freenasOS.Installer
class InstallationHandler(object):
    def __init__(self):
        self.package = None
        self.gauge = None
        
    def __enter__(self):
        return self

    def __exit__(sef, type, value, traceback):
        pass

    def start_package(self, index, name, packages):
        self.package = name
        total = len(packages)
        self.gauge = Dialog.Gauge(Title(),
                                  "Installing package {} ({} of {})".format(name,
                                                                            index, total),
                                  height=8, width=50)
        self.gauge.clear()
        self.gauge.run()

    def package_update(self, **kwargs):
        """
        Called on a per-package update, similar to downloading progress.
        """
        total = kwargs.pop("total", 0)
        index = kwargs.pop("index", 0)
        name = kwargs.pop("name", None)
        done = kwargs.pop("done", False)

        if done:
            self.gauge.percentage = 100
            # This causes the gauge to clean up
            self.gauge.result
            self.gauge = None
        else:
            # This is going to be very verbose -- it's each FS object
            LogIt("Package {}:  {}".format(self.package, name))
            self.gauge.percentage = int((index * 100) / total)
            
# This is set by SelectDisks, even if the drives
# aren't going to be re-used.
# Note that if there are multiple freenas-boot pools
# importable, the whole installation will exit, so
# this will either be none, or an importable pool object.
found_bootpool = None

def validate_disk(name):
    """
    Given the geom of a disk, let's see if it's appropriate.
    Innappropriate disks are too small (4gbytes and less),
    or are already mounted / in use by a pool.  (That latter
    being somewhat harder to tell...)
    XXX How inefficient is this?
    """
    min_disk_size = 4 * 1024 * 1024 * 1024
    used_disks = []
    # Start with zfs disks
    pools = list(zfs.pools)
    for pool in zfs.pools:
        for disk in pool.disks:
            # Remove the beginning "/dev/"
            disk_name = disk[5:]
            x = geom.geom_by_name("DEV", disk_name)
            used_disks.append(DiskRealName(x))
                
    # Now let's go for the mounted disks
    mounts = bsd.getmntinfo()
    for mount in mounts:
        if mount.fstype in ("tmpfs", "devfs"):
            # It's not a real disk!
            continue
        if mount.source.startswith("/dev/"):
            disk_name = mount.source[5:]
            x = geom.geom_by_name("DEV", disk_name)
            used_disks.append(DiskRealName(x))

    if name in used_disks:
        return False
    try:
        disk = Utils.Disk(name)
    except RuntimeError:
        LogIt("Could not find information about disk {} in validate_disk".format(name))
        return False
    if disk.size < min_disk_size:
        LogIt("Disk {} is too small ({}, need 4G at least)".format(name, disk.smart_size))
        return False
    return True

def validate_system():
    """
    At this point, all this does is check memory size -- Corral
    needs 8gbytes of ram.  (Which we'll check against 7gbytes,
    for Reasons.)  It should potentially do more.
    """
    gByte = 1024 * 1024 * 1024
    min_memsize = 7 * gByte
    try:
        sys_memsize = sysctlbyname("hw.physmem")
    except:
        LogIt("Could not determine system memory size")
        return False
    if sys_memsize <= min_memsize:
        LogIt("System memory size ({}) is lss than minimum ({})".format(sys_memsize, min_memsize))
        return False
    return True

def UpgradePossible():
    """
    An upgrade is possible if there is one (and only one) freenas-boot pool,
    and if that pool has an installation for the same project as us.  We'll
    determine the project by importing the pool, checking for a bootfs dataset,
    and mounting it to look at etc/version, which should startwith the same
    name as our project.  If any of those actions fail, return false.
    """
    global found_bootpool
    if not found_bootpool:
        LogIt("Boot pool has not been found, so no upgrade is possible")
        return False
    
    status = Dialog.MessageBox(Title(),
                      "Checking for upgradable {} installation".format(Project()),
                      width=45, height=10, wait=False)
    status.clear()
    status.run()
    try:
        try:
            zfs.import_pool(found_bootpool, "freenas-boot", {})
        except:
            LogIt("Could not import freenas-boot")
            return False
        boot_pool = None
        try:
            boot_pool = zfs.get("freenas-boot")
            try:
                bootfs = boot_pool.properties["bootfs"].value
                LogIt("bootfs = {}".format(bootfs))
                # Next we try to mount it
                try:
                    bsd.nmount(source=bootfs,
                               fspath="/mnt",
                               fstype="zfs",
                               flags=bsd.MountFlags.RDONLY,
                    )
                except BaseException as e:
                    LogIt("Couldn't mount, got exception {}".format(e))
                    raise
                try:
                    with open("/mnt/etc/version") as f:
                        version = f.read().rstrip()
                    if version.startswith(Project()):
                        return True
                    LogIt("{} does not start with {}".format(version, Project()))
                except:
                    LogIt("Could not open version file")
                    pass
                finally:
                    bsd.unmount("/mnt")
            except:
                    LogIt("Could not get bootfs property, or mount dataset")

        except:
            LogIt("Could not get freenas-boot pool")
        finally:
            if boot_pool:
                zfs.export_pool(boot_pool)
    except:
        LogIt("Could not find unimported freenas-boot pool")
    LogIt("Returning false")
    return False

def SelectDisks():
    """
    Select disks for installation.
    If there is already a freenas-boot pool, then it will first offer to
    reuse those disks.  Otherwise, it presents a menu of disks to select.
    It excludes any disk that is less than 4Gbytes.

    Returns either an array of Disk objects, or None.
    """
    global found_bootpool
    found_bootpool = None
    # Look for an existing freenas-boot pool, and ask about just using that.
    status = Dialog.MessageBox(Title(),
                               "Scanning for existing boot pools",
                               height=10, width=40, wait=False)
    status.clear()
    status.run()
    
    # First see if there is an existing boot pool
    try:
        pool = zfs.get("freenas-boot")
    except:
        pool = None

    if pool:
        Dialog.MessageBox(Title(),
                          "There is already an imported boot pool, and the {} installer cannot continue".format(Project()),
                          height=15, width=45).run()
        raise InstallationError("Boot pool is already imported")
    
    try:
        pools = list(zfs.find_import(name="freenas-boot"))
    except:
        pools = None

    if pools:
        if len(pools) > 1:
            box = Dialog.MessageBox(Title(),
                                    "There are {} unimported boot pools, this needs to be resolved.".format(len(pools)),
                                    height=15, width=45)
            box.run()
            raise InstallationError("Multiple unimported boot pools")
        else:
            pool_disks = [disk[5:] for disk in pools[0].disks]
            complete = True
            disks = []
            for disk in pool_disks:
                try:
                    found = Utils.Disk(disk)
                    disks.append(found)
                except RuntimeError:
                    complete = False

            if complete:
                found_bootpool = pools[0]
                title = "An existing boot pool was found"
                text = """The following disks are already in a boot pool.
Do you want to use them for the installation?
(Even if you want to re-format, but still use only these disks, select Yes.)\n\n"""
                text += "* " + ", ".join([disk.name for disk in disks])
                box = Dialog.YesNo(title, text, height=15, width=60, default=True)
                box.yes_label = "Yes"
                box.no_label = "No"
                reuse = False
                # Let an escape exception percolate up
                reuse = box.result
                if reuse:
                    return disks

    disks = list(geom.class_by_name("DISK").geoms)
    disks_menu = []
    for disk in disks:
        diskSize = int(disk.provider.mediasize / (1024 * 1024 * 1024))
        diskDescr = disk.provider.description[:20]
        if diskSize < 4:
            # 4GBytes or less is just too small
            continue
        # Also want to see if the disk is currently mounted
        if not validate_disk(disk.name):
            continue
        
        disks_menu.append(Dialog.ListItem(disk.name, "{} ({}GBytes)".format(diskDescr, diskSize)))
    if len(disks_menu) == 0:
        try:
            box = Dialog.MessageBox("No suitable disks were found for installation", width=60)
            box.run()
        except:
            pass
        return None
    
    disk_selector = Dialog.CheckList("Installation Media", "Select installation device(s)",
                                     height=20, width=60, list_items=disks_menu)
    # Let an escape exception percolate up
    selected_disks = disk_selector.result

    if selected_disks:
        return [Utils.Disk(entry.label) for entry in selected_disks]
    return None

def do_install():
    """
    Do the UI for the install.
    This will either return, or raise an exception.  DialogEscape means that
    the installer should start over.
    
    If we have any command-line arguments, let's handle them now
    """
    arg_parser = argparse.ArgumentParser(description=Title(), prog="Installer")
    arg_parser.register('type', 'bool', lambda x: x.lower() in ["yes", "y", "true", "t"])
    arg_parser.add_argument('-p', '--project',
                            dest='project',
                            default=Project(),
                            help="Specify project (default {})".format(Project()))
    arg_parser.add_argument('-T', '--train',
                            dest="train",
                            help="Specify train name")
    arg_parser.add_argument('-U', '--url',
                            dest="url",
                            help="URL to use when fetching files")
    arg_parser.add_argument('-M', '--manifest',
                            dest='manifest',
                            help="Path to manifest file")
    arg_parser.add_argument('-P', '--packages',
                            dest='package_dir',
                            help='Path to package files')
    arg_parser.add_argument("-B", "--trampoline",
                            dest='trampoline',
                            default=True,
                            type='bool',
                            help="Run post-install scripts on reboot (default)")
    args = arg_parser.parse_args()
    if args:
        LogIt("Command line args: {}".format(args))
        
    SetProject(args.project)
    
    if validate_system() is False:
        Dialog.MessageBox(Title(),
                           "\nSystem memory is too small.  Minimum memory size is 8Gbytes",
                           height=10, width=45).run()
        return
    
    if args.manifest:
        if os.path.exists(args.manifest):
            manifest_path = args.manifest
        else:
            Dialog.MessageBox(Title(),
                              "A manifest file was specified on the command line, but does not exist.  The manifest file specified was\n\n\t{}".format(args.manifest),
                              height=15, width=45).run()
            raise InstallationError("Command-line manifest file {} does not exist".foramt(args.manifet))
    else:
        manifest_path = "/.mount/{}-MANIFEST".format(Project())
        if not os.path.exists(manifest_path):
            manifest_path = None
            
    package_dir = args.package_dir or "/.mount/{}/Packages".format(Project())
    if not os.path.exists(package_dir):
        # This will be used later to see if we should try downloading
        package_dir = None
    # If we aren't given a URL, we can try to use the default url.
    # If we have a manifest file, we can figure out train;
    # if we don't have a train or manifest file, we're not okay.
    if (not manifest_path and not args.train):
        LogIt("Command-line URL {}, train {}, manifest {}".format(args.url, args.train, manifest_path))
        box = Dialog.MessageBox(Title(), "",
                                height=15, width=45)
        box.text = "Neither a manifest file nor train were specified"
        box.run()
        raise InstallationError("Incorrect command-line arguments given")
        
    conf = Configuration.SystemConfiguration()
    if conf is None:
        raise RuntimeError("No configuration?!")
    
    # Okay, if we're going to have to download, let's make an update server object
    if args.url:
        temp_update_server = Configuration.UpdateServer(name="Installer Server",
                                                        url=args.url,
                                                        signing=False)
        # This is SO cheating
        # It can't write to the file, but it does that after setting it.
        try:
            conf.AddUpdateServer(temp_update_server)
        except:
            pass
        conf.SetUpdateServer("Installer Server", save=False)
        
    # If we have a train, and no manifest file, let's grab one

    if manifest_path:
        manifest = Manifest.Manifest()
        try:
            manifest.LoadPath(manifest_path)
        except:
            manifest = None
    else:
        manifest = None
        
    if args.train and not manifest:
        try:
            status = Dialog.MessageBox(Title(),
                                       "Attempting to download manifest for train {}".format(args.train),
                                       height=15, width=30, wait=False)
            status.clear()
            status.run()
        except:
            pass
        try:
            manifest = conf.FindLatestManifest(train=args.train,
                                               require_signature=False)
        except:
            manifest = None
            
    # At this point, if we don't have a manifest, we can't do anything
    if manifest is None:
        LogIt("Could not load a manifest")
        text = "Despite valiant efforts, no manifest file could be located."

        Dialog.MessageBox(Title(),
                          text,
                          height=15, width=30).run()
        raise InstallationError("Unable to locate a manifest file")
    
    LogIt("Manifest:  Version {}, Train {}, Sequence {}".format(manifest.Version(),
                                                                manifest.Train(),
                                                                manifest.Sequence()))
    do_upgrade = False
    boot_method = None
    disks = SelectDisks()
    if not disks:
        try:
            Dialog.MessageBox(Title(),
                              "No suitable disks were found for installation",
                              height=15, width=60).run()
        except:
            pass
        raise InstallationError("No disks selected for installation")
    
    if found_bootpool:
        if UpgradePossible():
            text = """The {} installer can upgrade the existing {} installation.
Do you want to upgrade?""".format(Project(), Project())
            yesno = Dialog.YesNo("Perform Upgrade", text, height=12, width=60,
                                 yes_label="Upgrade", no_label="Do not Upgrade",
                                 default=True)
            do_upgrade = yesno.result
        else:
            Dialog.MessageBox("No upgrade possible", "").run()

    format_disks = True
    if found_bootpool:
        # If the selected disks are not the same as the existing boot-pool
        # disks, then we _will_ be formatting, and do not ask this question.
        disk_set = set([x.name for x in disks])
        pool_set = set([Utils.Disk(x).name for x in found_bootpool.disks])
        LogIt("disk_set = {}, pool_set = {}".format(disk_set, pool_set))
        if pool_set == disk_set:
            yesno = Dialog.YesNo(Title(),
                                 "The {} installer can reformat the disk{}, or create a new boot environment.\nReformatting will erase all of your data".format(Project(), "s" if len(disks) > 1 else ""),
                                 height=10, width=60,
                                 yes_label="Re-format",
                                 no_label="Create New BE", default=True)
            format_disks = yesno.result
            yesno.clear()

    if format_disks:
        # If there is already a freenas-boot, and we're not using all of
        # the disks in it, then this will cause problems.
        # If we made it this far, there is only one freenas-boot pool.
        if found_bootpool:
            pool_disks = [Utils.Disk(x) for x in found_bootpool.disks]

            disk_set = set([x.name for x in disks])
            pool_set = set([x.name for x in pool_disks])
            LogIt("disk_set = {}, pool_set = {}".format(disk_set, pool_set))
            if not pool_set <= disk_set:
                # This means there would be two freenas-boot pools, which
                # is too much of a problem.
                yesno = Dialog.YesNo(Title(),
                                        "The existing boot pool contains disks that are not in the selected set of disks, which would result in errors.  Select Start Over, or press Escape, otherwise the {} installer will destroy the existing pool".format(Project()),
                                     width=60,
                                     yes_label="Destroy Pool",
                                     no_label="Start over",
                                     default=False)
                yesno.prompt += "\nSelected Disks: " + " ,".join(sorted([x.name for x in disks]))
                yesno.prompt += "\nPool Disks:     " + " ,".join(sorted([x.name for x in pool_disks]))
                if yesno.result is False:
                    raise Dialog.DialogEscape

        current_method = BootMethod()
        yesno = Dialog.YesNo("Boot Method",
                             "{} can boot via BIOS or (U)EFI.  Selecting the wrong method can result in a non-bootable system".format(Project()),
                             height=10, width=60,
                             yes_label="BIOS",
                             no_label="(U)EFI",
                             default=False if current_method == "efi" else True)
        if yesno.result is True:
            boot_method = "bios"
        else:
            boot_method = "efi"

    if not do_upgrade:
        # Ask for root password
        while True:
            password_fields = [
                Dialog.FormItem(Dialog.FormLabel("Password:"),
                                 Dialog.FormInput("", width=20, maximum_input=50, hidden=True)),
                Dialog.FormItem(Dialog.FormLabel("Confirm Password:"),
                                 Dialog.FormInput("", width=20, maximum_input=50, hidden=True)),
            ]
            try:
                password_input = Dialog.Form("Root Password",
                                             "Enter the root password.  (Escape to quit, or select No Password)",
                                             width=60, height=15,
                                             cancel_label="No Password",
                                             form_height=10, form_items=password_fields)
                results = password_input.result
                if results and results[0].value.value != results[1].value.value:
                    Dialog.MessageBox("Password Error",
                                      "Passwords did not match",
                                      width=35,
                                      ok_label="Try again").run()
                    continue
                else:
                    new_password = results[0].value.value if results else None
                    break
            except Dialog.DialogEscape:
                try:
                    Diallog.MessageBox("No Password Selected",
                                       "You have selected an empty password",
                                       height=7, width=35).run()
                except:
                    pass
                new_password = None
                break
                    
    # I'm not sure if this should be done here, or in Install()

    if package_dir is None:
        cache_dir = tempfile.mkdtemp()
    else:
        cache_dir = package_dir

    try:
        Utils.GetPackages(manifest, conf, cache_dir, interactive=True)
    except BaseException as e:
        LogIt("GetPackages raised an exception {}".format(str(e)))
        if package_dir is None:
            shutil.rmtree(cache_dir, ignore_errors=True)
        raise
    LogIt("Done getting packages?")
    # Let's confirm everything
    text = "The {} Installer will perform the following actions:\n\n".format(Project())
    height = 10
    if format_disks:
        text += "* The following disks will be reformatted, and all data lost:\n"
        height += 1
        for disk in disks:
            text += "\t* {} {} ({}bytes)\n".format(disk.name,
                                                   disk.description[:25],
                                                   SmartSize(disk.size))
            height += 1
        if found_bootpool:
            text += "* The existing boot pool will be destroyed\n"
            height += 1
        text += "* {} Booting\n".format("BIOS" if boot_method is "bios" else "(U)EFI")
    else:
        text += "* A new Boot Environment will be created\n"
        height += 1
        
    if do_upgrade:
        text += "* {} will be upgraded\n".format(Project())
    else:
        text += "* {} will be freshly installed\n".format(Project())
    height += 1
    
    yesno.prompt = text
    yesno.default = False
    yesno = Dialog.YesNo("{} Installation Confirmation".format(Project()),
                         text,
                         height=height, width=60,
                         yes_label="Continue",
                         no_label="Cancel",
                         default=False)
    if yesno.result == False:
        LogIt("Installation aborted at first confirmation")
        raise Dialog.DialogEscape
    
    if format_disks:
        yesno = Dialog.YesNo("LAST CHANCE",
                             "The {} installer will format the selected disks and all data on them will be erased.\n\nSelect Start Over or hit Escape to start over!".format(Project()),
                             height=10,
                             width=50,
                             yes_label="Continue",
                             no_label="Start Over",
                             default=False)
        if yesno.result is False:
            LogIt("Installation aborted at second confirmation")
            raise Dialog.DialogEscape
        
    # This may take a while, it turns out
    try:
        status = Dialog.MessageBox(Title(), "\nBeginning installation",
                                   height=7, width=25, wait=False)
        status.clear()
        status.run()
    except:
        pass
    # Okay, time to do the install
    with InstallationHandler() as handler:
        try:
            Install.Install(interactive=True,
                            manifest=manifest,
                            config=conf,
                            package_directory=cache_dir,
                            disks=disks if format_disks else None,
                            efi=True if boot_method is "efi" else False,
                            upgrade_from=found_bootpool if found_bootpool else None,
                            upgrade=do_upgrade,
                            package_handler=handler.start_package,
                            progress_handler=handler.package_update,
                            password=None if do_upgrade else new_password,
                            trampoline=args.trampoline)
        except BaseException as e:
            LogIt("Install got exception {}".format(str(e)))
            raise
    return

def do_shell():
    shell = os.environ["SHELL"] if "SHELL" in os.environ else "/bin/sh"
    try:
        subprocess.call(shell)
    except:
        pass
    return

def do_reboot():
    LogIt("Reboot")
    try:
        RunCommand("/sbin/dmesg", "-c")
    except:
        pass
    try:
        RunCommand("/sbin/reboot")
    except:
        pass
    sys.exit(2)

def do_shutdown():
    LogIt("Shutdown")
    try:
        RunCommand("/sbin/halt", "-p")
    except:
        pass
    sys.exit(1)

def do_exit():
    print("In do_exit")
    sys.exit(0)
    
def main():
    InitLog()
    
    menu_actions = [
        ("Install/Update" , do_install),
        ("Shell" , do_shell),
        ("Reboot" , do_reboot),
        ("Shutdown" , do_shutdown),
        ("Exit" , do_exit),
        ]
    menu_items = [Dialog.FormLabel(x[0]) for x in menu_actions]
    menu_dict = { x[0] : x[1] for x in menu_actions}
    while True:
        menu = Dialog.Menu("Installation Menu", "", height=12, width=60,
                           menu_items=menu_items)
        try:
            result = menu.result
            if result in menu_dict:
                try:
                    menu_dict[result]()
                except InstallationError as e:
                    LogIt("Got InstallationError {}".format(str(e)))
                    try:
                        Dialog.MessageBox(Title(),
                                          "An installation error has occurred.",
                                          height=5, width=40).run()
                    except:
                        pass
                except Dialog.DialogEscape:
                    LogIt("Got a DialogEscape after calling {}".format(result))
        except Dialog.DialogEscape as e:
            LogIt("Got DialogEscape for main menu, exiting")
            sys.exit(0)
        except SystemExit as e:
            LogIt("Got system exit {}".format(e.code))
            sys.exit(e.code)
        except BaseException as e:
            print("Got exception {}".format(str(e)))

if __name__ == "__main__":
    main()
