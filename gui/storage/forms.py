#+
# Copyright 2010 iXsystems
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# $FreeBSD$
#####################################################################
from dojango import forms
from django.shortcuts import render_to_response
from freenasUI.storage.models import *
from freenasUI.middleware.notifier import notifier
from django.http import HttpResponseRedirect
from django.utils.safestring import mark_safe
from django.utils.encoding import force_unicode
from dojango.forms import fields, widgets
from freenasUI.common.forms import ModelForm
from freenasUI.common.forms import Form
from dojango.forms.fields import BooleanField
from freenasUI.contrib.ext_formwizard import FormWizard
from freenasUI.common.widgets import RadioFieldRendererBulletless
from freenasUI.account.models import bsdUsers, bsdGroups

attrs_dict = { 'class': 'required' }

class VolumeWizardForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super(VolumeWizardForm, self).__init__(*args, **kwargs)
        self.fields['volume_disks'].choices = self._populate_disk_choices()
        self.fields['volume_disks'].choices.sort()
        self.fields['volume_fstype'].widget.attrs['onClick'] = 'wizardcheckings();'

        grouptype_choices = ( ('mirror', 'mirror'), )
        grouptype_choices += ( ('stripe', 'stripe'),)
        fstype = self.data.get("volume_fstype", None)
        disks = self.data.get("volume_disks", [])
        if fstype == "UFS":
            l = len(disks) - 1
            if l >= 2 and (((l-1)&l) == 0):
                grouptype_choices += (
                    ('raid3', 'RAID-3'),
                    )
        elif fstype == "ZFS":
            if len(disks) >= 3:
                grouptype_choices += ( ('raidz', 'RAID-Z'), )
            if len(disks) >= 4:
                grouptype_choices += ( ('raidz2', 'RAID-Z2'), )
            # Not yet
            #if len(disks) >= 5:
            #    grouptype_choices += ( ('raidz3', 'RAID-Z3'), )
        self.fields['group_type'].choices = grouptype_choices

    def _populate_disk_choices(self):
        from os import popen
        import re
    
        diskchoices = dict()
    
        # Grab disk list
        # NOTE: This approach may fail if device nodes are not accessible.
        pipe = popen("/usr/sbin/diskinfo `/sbin/sysctl -n kern.disks | tr ' ' '\n' | grep -v '^cd[0-9]'` | /usr/bin/cut -f1,3")
        diskinfo = pipe.read().strip().split('\n')
        for disk in diskinfo:
            devname, capacity = disk.split('\t')
            capacity = int(capacity)
            if capacity >= 1099511627776:
                    capacity = "%.1f TiB" % (capacity / 1099511627776.0)
            elif capacity >= 1073741824:
                    capacity = "%.1f GiB" % (capacity / 1073741824.0)
            elif capacity >= 1048576:
                    capacity = "%.1f MiB" % (capacity / 1048576.0)
            else:
                    capacity = "%d Bytes" % (capacity)
            diskchoices[devname] = "%s (%s)" % (devname, capacity)
        # Exclude the root device
        rootdev = popen("""glabel status | grep `mount | awk '$3 == "/" {print $1}' | sed -e 's/\/dev\///'` | awk '{print $3}'""").read().strip()
        rootdev_base = re.search('[a-z/]*[0-9]*', rootdev)
        if rootdev_base != None:
            try:
                del diskchoices[rootdev_base.group(0)]
            except:
                pass
        # Exclude what's already added
        for devname in [ x['disk_disks'] for x in Disk.objects.all().values('disk_disks')]:
            try:
                del diskchoices[devname]
            except:
                pass
        return diskchoices.items()

    #def clean(self):
    #    cleaned_data = self.cleaned_data
    #    volume_name = cleaned_data.get("volume_name")
    #    if Volume.objects.filter(vol_name = volume_name).count() > 0:
    #        msg = u"You already have a volume with same name"
    #        self._errors["volume_name"] = self.error_class([msg])
    #        del cleaned_data["volume_name"]
    #    return cleaned_data

    def done(self):
        # Construct and fill forms into database.
        volume_name = self.cleaned_data['volume_name']
        volume_fstype = self.cleaned_data['volume_fstype']
        disk_list = self.cleaned_data['volume_disks']

        if (len(disk_list) < 2):
            group_type = ''
        else:
            group_type = self.cleaned_data['group_type']

        volume = Volume(vol_name = volume_name, vol_fstype = volume_fstype)
        volume.save()

        mp = MountPoint(mp_volume=volume, mp_path='/mnt/' + volume_name, mp_options='rw')
        mp.save()

        grp = DiskGroup(group_name= volume_name + group_type, group_type = group_type, group_volume = volume)
        grp.save()

        for diskname in disk_list:
            diskobj = Disk(disk_name = diskname, disk_disks = diskname,
                           disk_description = ("Member of %s %s" %
                                              (volume_name, group_type)),
                           disk_group = grp)
            diskobj.save()

        notifier().init("volume", volume.id)

    volume_name = forms.CharField(max_length = 30, label = 'Volume name')
    volume_fstype = forms.ChoiceField(choices = ((x, x) for x in ('UFS', 'ZFS')), widget=forms.RadioSelect(attrs=attrs_dict), label = 'File System type')
    volume_disks = forms.MultipleChoiceField(choices=(), widget=forms.SelectMultiple(attrs=attrs_dict), label = 'Member disks')
    group_type = forms.ChoiceField(choices=(), widget=forms.RadioSelect(attrs=attrs_dict), required=False)

    def clean_group_type(self):
        if len(self.data['volume_disks']) > 1 and self.cleaned_data['group_type'] in (None, ''):
            raise forms.ValidationError("This field is required.")
        return self.cleaned_data['group_type']

# Step 1.  Creation of volumes manually is not supported.
class VolumeWizard_VolumeNameTypeForm(Form):
    def __init__(self, *args, **kwargs):
        super(VolumeWizard_VolumeNameTypeForm, self).__init__(*args, **kwargs)
        self.fields['volume_disks'].choices = self._populate_disk_choices()
        self.fields['volume_disks'].choices.sort()
    def _populate_disk_choices(self):
        from os import popen
        import re
    
        diskchoices = dict()
    
        # Grab disk list
        # NOTE: This approach may fail if device nodes are not accessible.
        pipe = popen("/usr/sbin/diskinfo `/sbin/sysctl -n kern.disks | tr ' ' '\n' | grep -v '^cd[0-9]'` | /usr/bin/cut -f1,3")
        diskinfo = pipe.read().strip().split('\n')
        for disk in diskinfo:
            devname, capacity = disk.split('\t')
            capacity = int(capacity)
            if capacity >= 1099511627776:
                    capacity = "%.1f TiB" % (capacity / 1099511627776.0)
            elif capacity >= 1073741824:
                    capacity = "%.1f GiB" % (capacity / 1073741824.0)
            elif capacity >= 1048576:
                    capacity = "%.1f MiB" % (capacity / 1048576.0)
            else:
                    capacity = "%d Bytes" % (capacity)
            diskchoices[devname] = "%s (%s)" % (devname, capacity)
        # Exclude the root device
        rootdev = popen("""glabel status | grep `mount | awk '$3 == "/" {print $1}' | sed -e 's/\/dev\///'` | awk '{print $3}'""").read().strip()
        rootdev_base = re.search('[a-z/]*[0-9]*', rootdev)
        if rootdev_base != None:
            try:
                del diskchoices[rootdev_base.group(0)]
            except:
                pass
        # Exclude what's already added
        for devname in [ x['disk_disks'] for x in Disk.objects.all().values('disk_disks')]:
            try:
                del diskchoices[devname]
            except:
                pass
        return diskchoices.items()
    def clean(self):
        cleaned_data = self.cleaned_data
        volume_name = cleaned_data.get("volume_name")
	if Volume.objects.filter(vol_name = volume_name).count() > 0:
                msg = u"You already have a volume with same name"
                self._errors["volume_name"] = self.error_class([msg])
                del cleaned_data["volume_name"]
        return cleaned_data
    volume_name = forms.CharField(max_length = 30, label = 'Volume name')
    #volume_fstype = forms.ChoiceField(choices = ((x, x) for x in ('UFS', 'ZFS')), widget=forms.RadioSelect(attrs=attrs_dict, renderer=RadioFieldRendererBulletless), label = 'File System type')
    volume_fstype = forms.ChoiceField(choices = ((x, x) for x in ('UFS', 'ZFS')), widget=forms.RadioSelect(attrs=attrs_dict), label = 'File System type')
    volume_disks = forms.MultipleChoiceField(choices=(), widget=forms.SelectMultiple(attrs=attrs_dict), label = 'Member disks')

# Step 2.  Creation of volumes manually is not supported.
# This step only show up when more than 1 disks is being chosen.
class VolumeWizard_DiskGroupTypeForm(Form):
    def __init__(self, *args, **kwargs):
        super(VolumeWizard_DiskGroupTypeForm, self).__init__(*args, **kwargs)
        grouptype_choices = ( ('mirror', 'mirror'), )
        fstype = kwargs['initial']['fstype']
        disks =  kwargs['initial']['disks']
        grouptype_choices += (
            ('stripe', 'stripe'),
            )
        if fstype == "UFS":
            l = len(disks) - 1
            if l >= 2 and (((l-1)&l) == 0):
                grouptype_choices += (
                    ('raid3', 'RAID-3'),
                    )
        elif fstype == "ZFS":
            if len(disks) >= 3:
                grouptype_choices += ( ('raidz', 'RAID-Z'), )
            if len(disks) >= 4:
                grouptype_choices += ( ('raidz2', 'RAID-Z2'), )
            # Not yet
            #if len(disks) >= 5:
            #    grouptype_choices += ( ('raidz3', 'RAID-Z3'), )
        self.fields['group_type'].choices = grouptype_choices
    group_type = forms.ChoiceField(choices=(), widget=forms.RadioSelect(attrs=attrs_dict))

# Step 3.  Just show a page with "Finish".
class VolumeFinalizeForm(Form):
    pass

#=================================

# A partial form for editing disk.
# we only show disk_name (used as GPT label), disk_disks
# (device name), and disk_group (which group this disk belongs
# to), but don't allow editing.
class DiskFormPartial(ModelForm):
    class Meta:
        model = Disk
    def __init__(self, *args, **kwargs):
        super(DiskFormPartial, self).__init__(*args, **kwargs)
        instance = getattr(self, 'instance', None)
        if instance and instance.id:
            self.fields['disk_name'].widget.attrs['readonly'] = True
            self.fields['disk_disks'].widget.attrs['readonly'] = True
            self.fields['disk_group'].widget.attrs['readonly'] = True
    def clean_disk_name(self):
        return self.instance.disk_name
    def clean_disk_disks(self):
        return self.instance.disk_disks
    def clean_disk_group(self):
        return self.instance.disk_group

#=================================
# Finally, the wizard.

class VolumeWizard(FormWizard):
    def __init__(self, *args, **kwargs):
            super(VolumeWizard, self).__init__(*args, **kwargs)
            self.extra_context = {'mp_list': MountPoint.objects.select_related().all()}
    def process_step(self, request, form, step):
        if step==0:
            disks = form.cleaned_data['volume_disks']
            if self.step <= step:
                if (len(disks) < 2):
	            self.form_list.remove(VolumeWizard_DiskGroupTypeForm)
                else:
                    self.initial[1] = {
                            'fstype': form.cleaned_data['volume_fstype'],
                            'disks': disks
                            }
            elif len(disks) < 2:
	        self.form_list.remove(VolumeWizard_DiskGroupTypeForm)
    def get_template(self, step):
        return 'storage/wizard.html'
    def done(self, request, form_list):
        # Construct and fill forms into database.
        #
        volume_name = form_list[0].cleaned_data['volume_name']
        volume_fstype = form_list[0].cleaned_data['volume_fstype']
        disk_list = form_list[0].cleaned_data['volume_disks']

        if (len(disk_list) < 2):
            group_type = ''
        else:
            group_type = form_list[1].cleaned_data['group_type']

        volume = Volume(vol_name = volume_name, vol_fstype = volume_fstype)
        volume.save()

        mp = MountPoint(mp_volume=volume, mp_path='/mnt/' + volume_name, mp_options='rw')
        mp.save()

        grp = DiskGroup(group_name= volume_name + group_type, group_type = group_type, group_volume = volume)
        grp.save()

        for diskname in disk_list:
            diskobj = Disk(disk_name = diskname, disk_disks = diskname,
                           disk_description = ("Member of %s %s" %
                                              (volume_name, group_type)),
                           disk_group = grp)
            diskobj.save()

	notifier().init("volume", volume.id)
        notifier().restart("collectd")
        return HttpResponseRedirect('/storage/')

# Wrapper for the wizard.  Without the wrapper we end up
# messing with data in the global urls object which makes
# it impossible to re-enter the wizard for the second time.
def VolumeWizard_wrapper(request, *args, **kwargs):
	return VolumeWizard([VolumeWizard_VolumeNameTypeForm, VolumeWizard_DiskGroupTypeForm, VolumeFinalizeForm], error_redirect="/storage/")(request, *args, **kwargs)

class ZFSDataset_CreateForm(Form):
    def __init__(self, *args, **kwargs):
        super(ZFSDataset_CreateForm, self).__init__(*args, **kwargs)
        self.fields['dataset_volid'].choices = self._populate_volume_choices()
    def _populate_volume_choices(self):
        volumechoices = dict()
        volumes = Volume.objects.filter(vol_fstype='ZFS')
        for volume in volumes:
            volumechoices[volume.id] = volume.vol_name
        return volumechoices.items()
    def clean(self):
        cleaned_data = self.cleaned_data
        volume_name = Volume.objects.get(id=cleaned_data.get("dataset_volid")).vol_name.__str__()
        full_dataset_name = "%s/%s" % (volume_name, cleaned_data.get("dataset_name").__str__())
        if len(notifier().list_zfs_datasets(path=full_dataset_name)) > 0:
            msg = u"You already have a dataset with the same name"
            self._errors["dataset_name"] = self.error_class([msg])
            del cleaned_data["dataset_name"]
        return cleaned_data
    dataset_volid = forms.ChoiceField(choices=(), widget=forms.Select(attrs=attrs_dict),  label='Volume from which this dataset will be created on')
    dataset_name = forms.CharField(max_length = 128, label = 'Dataset Name')
    dataset_compression = forms.ChoiceField(choices=ZFS_CompressionChoices, widget=forms.Select(attrs=attrs_dict), label='Compression level')
    dataset_atime = forms.ChoiceField(choices=ZFS_AtimeChoices, widget=forms.RadioSelect(attrs=attrs_dict), label='Enable atime')

class MountPointAccessForm(Form):
    mp_user = forms.ChoiceField(choices=(), widget=forms.Select(attrs=attrs_dict), label='Owner (user)')
    mp_group = forms.ChoiceField(choices=(), widget=forms.Select(attrs=attrs_dict), label='Owner (group)')
    mp_mode = forms.ChoiceField(choices=PermissionChoices, widget=forms.Select(attrs=attrs_dict), label='Mode')
    mp_recursive = forms.BooleanField(initial=False,required=False,label='Set permission recursively')
    def __init__(self, *args, **kwargs):
        super(MountPointAccessForm, self).__init__(*args, **kwargs)
        self.fields['mp_user'].choices = [(x.bsdusr_username, x.bsdusr_username) for x in bsdUsers.objects.all()]
        self.fields['mp_group'].choices = [(x.bsdgrp_group, x.bsdgrp_group) for x in bsdGroups.objects.all()]
    def commit(self, path='/mnt/'):
        notifier().mp_change_permission(
            path=path,
            user=self.cleaned_data['mp_user'].__str__(),
            group=self.cleaned_data['mp_group'].__str__(),
            mode=self.cleaned_data['mp_mode'].__str__(),
            recursive=self.cleaned_data['mp_recursive'])

