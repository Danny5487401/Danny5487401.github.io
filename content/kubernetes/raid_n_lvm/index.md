---
title: "存储: Raid 和 lvm"
date: 2025-02-21T08:34:31+08:00
summary: raid 和 lvm 在 k8s中应用
categories:
  - kubernetes
  - raid
  - lvm
---


## 基本命令

### lsblk (list block)

列出所有可用块设备的信息，而且还能显示他们之间的依赖关系，但是它不会列出RAM盘的信息。块设备有硬盘，闪存盘，cd-ROM等等。

```shell
# lsblk 命令默认情况下将以树状列出所有块设备
$ lsblk

NAME   MAJ:MIN rm   SIZE RO type mountpoint
sda      8:0    0 232.9G  0 disk 
├─sda1   8:1    0  46.6G  0 part /
├─sda2   8:2    0     1K  0 part 
├─sda5   8:5    0   190M  0 part /boot
├─sda6   8:6    0   3.7G  0 part [SWAP]
├─sda7   8:7    0  93.1G  0 part /data
└─sda8   8:8    0  89.2G  0 part /personal
sr0     11:0    1  1024M  0 rom
```

### blkid (block id)

### parted 

fdisk,gdisk,parted 三种分区工具比较
- fdisk 只能用于MBR分区，gdisk,parted可以用于GPT分区。
- parted 命令在创建删除分区使用命令比较方便，但是功能不是太完善，没有备份还原命令。
- gdisk 在分区上命令和fdisk风格一样， 使用方便，学习难度低且功能强大，推荐使用。

```shell
[root@centos7 mnt]$ parted --help
Usage: parted [OPTION]... [DEVICE [COMMAND [PARAMETERS]...]...]
Apply COMMANDs with PARAMETERS to DEVICE.  If no COMMAND(s) are given, run in
interactive mode.

OPTIONs:
  -h, --help                      displays this help message
  -l, --list                      lists partition layout on all block devices
  -m, --machine                   displays machine parseable output
  -s, --script                    never prompts for user intervention
  -v, --version                   displays the version
  -a, --align=[none|cyl|min|opt]  alignment for new partitions

COMMANDs:
  align-check TYPE N                        check partition N for TYPE(min|opt)
        alignment
  help [COMMAND]                           print general help, or help on
        COMMAND
  mklabel,mktable LABEL-TYPE               create a new disklabel (partitionM                       # 设置分区类型 详细使用man获取
        table)
  mkpart PART-TYPE [FS-TYPE] START END     make a partition                                         # 创建一个分区 start,end为M，详细信息使用man获取
  name NUMBER NAME                         name partition NUMBER as NAME
  print [devices|free|list,all|NUMBER]     display the partition table,                             # 打印信息
        available devices, free space, all found partitions, or a particular
        partition
  quit                                     exit program                                             # 退出
  rescue START END                         rescue a lost partition near START                       # 救援一个丢失的分区
        and END
  rm NUMBER                                delete partition NUMBER                                  # 删除一个分区
  select DEVICE                            choose the device to edit                                # 选择一个分区去编辑
  disk_set FLAG STATE                      change the FLAG on selected device                       # 改变选择分区的标记
  disk_toggle [FLAG]                       toggle the state of FLAG on selected                     # 切换选择分区的标记
        device
  set NUMBER FLAG STATE                    change the FLAG on partition NUMBER                      # 改变指定分区号的标记
  toggle [NUMBER [FLAG]]                   toggle the state of FLAG on partition                    # 切换指定分区号的标记
        NUMBER
  unit UNIT                                set the default unit to UNIT                             # 设置默认单位
  version                                  display the version number and                           # 显示版本
        copyright information of GNU Parted

Report bugs to bug-parted@gnu.org
```
分区类型 
- primary：主分区
- logical：逻辑分区
- extended：扩展分区

GPT分区
/dev/sdb1分区类型为Linux LVM，大小为30G
/dev/sdb2分区类型为swap，大小为20G
/dev/sdb3分区类型为Linux，大小为10G
/dev/sdb4分区类型为linux,大小为10G
保留40G留作后用
```shell
[root@centos7 mnt]$ parted -s /dev/sdb mklabel gpt 
[root@centos7 mnt]$ parted -s /dev/sdb unit GB mkpart primary 1 30 set 1 lvm on
[root@centos7 mnt]$ parted -s /dev/sdb unit GB mkpart primary 30 50 set 2 swap on
[root@centos7 mnt]$ parted -s /dev/sdb unit GB mkpart primary 50 60
[root@centos7 mnt]$ parted -s /dev/sdb unit GB mkpart primary 60 70
[root@centos7 mnt]$ parted -s /dev/sdb print
```

### fuser - identify processer using files or sockets

fuser 可以显示出当前哪个程序在使用磁盘上的某个文件、挂载点、甚至网络端口，并给出程序进程的详细信息。

```shell
# 显示使用某个文件的进程信息 在umount的时候很有用，可以找到还有哪些用到这个设备了。
# 比如 lvremove -f /dev/sda2 报错 Logical volume /dev/sda2 contains a filesystem in use.
$ fuser --user --mount /dev/sda2 --kill --interactive
/dev/sda2:            6378c(quietheart)  6534c(quietheart)  6628(quietheart)  
6653c(quietheart)  7429c(quietheart)  7549c(quietheart)  7608c(quietheart) 
```

## lvm(Logical Volume Manager)
{{<figure src="./lvm_transfer.png#center" width=800px >}}

LVM是建立在硬盘和 分区之上的一个逻辑层，来提高磁盘分区管理的灵活性。
通过LVM系统管理员可以轻松管理磁盘分区，如：将若干个磁盘分区连接为一个整块的卷组 （volumeGroup），形成一个存储池。
管理员可以在卷组上随意创建逻辑卷组（logicalVolumes），并进一步在逻辑卷组上创建文件系 统。
管理员通过LVM可以方便的调整存储卷组的大小，并且可以对磁盘存储按照组的方式进行命名、管理和分配，例如按照使用用途进行定义：“development”和“sales”，而不是使用物理磁盘名“sda”和“sdb”。

{{<figure src="./lvm_structure.png#center" width=800px >}}

多个磁盘/分区/raid-->多个物理卷PV-->合成卷组VG-->从VG划分出逻辑卷LV-->格式化LV，挂载使用。

4个基本的逻辑卷概念。

①PE　　(Physical Extend)　　物理拓展

②PV　　(Physical Volume)　　物理卷

③VG　　(Volume Group)　　卷组

④LV　　(Logical Volume)　　逻辑卷

### lvm 操作


| 功能 |  PV管理命令   | VG管理命令 |LV管理命令 |
| :--: |:---------:| :--: |:--: |
| scan 扫描 |  pvscan   | vgscan |lvscan |
| create 创建 | pvcreate  | vgcreate |lvcreate |
| display 显示 | pvdisplay | vgdisplay |lvdisplay |
| remove 移除 | pvremove  | vgremove |lvremove |
| extend 扩展 |           | vgextend |lvextend |
| reduce 减少 |           | vgreduce |lvreduce |


lvcreate 使用
```go
// https://github.com/openebs/lvm-localpv/blob/9e0ac5b4a8bacb9dc771d8d6c33293070df71507/pkg/lvm/lvm_util.go

const (
    VGCreate = "vgcreate"
    VGList   = "vgs"
    
    LVCreate = "lvcreate"
    LVRemove = "lvremove"
    LVExtend = "lvextend"
    LVList   = "lvs"
    
    PVList = "pvs"
    PVScan = "pvscan"
    
    YES        = "yes"
    LVThinPool = "thin-pool"
)

// 创建 卷
func CreateVolume(vol *apis.LVMVolume) error {
	volume := vol.Spec.VolGroup + "/" + vol.Name

	volExists, err := CheckVolumeExists(vol)
	if err != nil {
		return err
	}
	if volExists {
		klog.Infof("lvm: volume (%s) already exists, skipping its creation", volume)
		return nil
	}

	args := buildLVMCreateArgs(vol)
	out, _, err := RunCommandSplit(LVCreate, args...)

	if err != nil {
		err = newExecError(out, err)
		klog.Errorf(
			"lvm: could not create volume %v cmd %v error: %s", volume, args, string(out),
		)
		return err
	}
	klog.Infof("lvm: created volume %s", volume)

	return nil
}

func buildLVMCreateArgs(vol *apis.LVMVolume) []string {
	var LVMVolArg []string

	volume := vol.Name
	size := vol.Spec.Capacity + "b"
	// thinpool name required for thinProvision volumes
	pool := vol.Spec.VolGroup + "_thinpool"

	if len(vol.Spec.Capacity) != 0 {
		// check if thin pool exists for given volumegroup requested thin volume
		if strings.TrimSpace(vol.Spec.ThinProvision) != YES {
			LVMVolArg = append(LVMVolArg, "-L", size)
		} else if !lvThinExists(vol.Spec.VolGroup, pool) {
			// thinpool size can't be equal or greater than actual volumegroup size
			LVMVolArg = append(LVMVolArg, "-L", getThinPoolSize(vol.Spec.VolGroup, vol.Spec.Capacity))
		}
	}

	// command to create thinpool and thin volume if thinProvision is enabled
	// `lvcreate -L 1G -T lvmvg/mythinpool -V 1G -n thinvol`
	if strings.TrimSpace(vol.Spec.ThinProvision) == YES {
		LVMVolArg = append(LVMVolArg, "-T", vol.Spec.VolGroup+"/"+pool, "-V", size)
	}

	if len(vol.Spec.VolGroup) != 0 {
		LVMVolArg = append(LVMVolArg, "-n", volume)
	}

	if strings.TrimSpace(vol.Spec.ThinProvision) != YES {
		LVMVolArg = append(LVMVolArg, vol.Spec.VolGroup)
	}

	// -y is used to wipe the signatures before creating LVM volume
	LVMVolArg = append(LVMVolArg, "-y")
	return LVMVolArg
}

```

lvs 使用
```go
func ListLVMLogicalVolume() ([]LogicalVolume, error) {
	args := []string{
		"--options", "lv_all,vg_name,segtype",
		"--reportformat", "json",
		"--units", "b",
	}
	output, _, err := RunCommandSplit(LVList, args...)
	if err != nil {
		klog.Errorf("lvm: error while running command %s %v: %v", LVList, args, err)
		return nil, err
	}

	return decodeLvsJSON(output)
}

```
pvs 使用
```go
func ListLVMPhysicalVolume() ([]PhysicalVolume, error) {
	if err := ReloadLVMMetadataCache(); err != nil {
		return nil, err
	}

	args := []string{
		"--options", "pv_all,vg_name",
		"--reportformat", "json",
		"--units", "b",
	}
	output, _, err := RunCommandSplit(PVList, args...)
	if err != nil {
		klog.Errorf("lvm: error while running command %s %v: %v", PVList, args, err)
		return nil, err
	}

	return decodePvsJSON(output)
}
```



建立物理卷和卷组: 增加了一块硬盘/dev/sdb, 创建三个分区，并建立三个物理卷 ，三个物理卷中前两个属于一个卷组VolGroup_data，最后一个属于卷组VolGroup_log.

整个LVM的工作原理：

(1)物理磁盘被格式化为PV，空间被划分为一个个的PE

(2)不同的PV加入到同一个VG中，不同PV的PE全部进入到了VG的PE池内

(3)LV基于PE创建，大小为PE的整数倍，组成LV的PE可能来自不同的物理磁盘

(4)LV直接可以格式化后挂载使用

(5)LV的扩充缩减实际上就是增加或减少组成该LV的PE数量，其过程不会丢失原始数据

```shell
# 1 创建分区

# 2 物理卷的创建(pvcreate): /dev/sdb1，/dev/sdb2, /dev/sdb3由分区转换成了物理卷
[root@localhost ~]# pvcreate /dev/sdb{1,2,3}
Writing physical volume data to disk "/dev/sdb1"
Physical volume "/dev/sdb1" successfully created
Writing physical volume data to disk "/dev/sdb2"
Physical volume "/dev/sdb2" successfully created
Writing physical volume data to disk "/dev/sdb3"
Physical volume "/dev/sdb3" successfully created


# 3 卷组的创建（vgcreate）: 每创建一个VG，其会在/dev目录下创建一个以该VG名字命名的文件夹
[root@localhost ~]# vgcreate VolGroup_data /dev/sdb1 /dev/sdb2
Volume group "VolGroup_data" successfully created
[root@localhost ~]# vgcreate VolGroup_log /dev/sdb3
Volume group "VolGroup_log" successfully created
```

建立逻辑卷并使用:
- VolGroup_log 中建立一个逻辑分区lv_log，文件系统为Ext4，大小为300MB，挂载点为/da/log。
- VolGroup_data 中建立一个逻辑分区 lv_data，文件系统为Ext4，大小为1.2GB，挂载点为 /da/data

{{<figure src="./lv_final.png#center" width=800px >}}
```shell
# 1 建立逻辑分区
[root@localhost ~]# lvcreate -L 300M -n lv_log VolGroup_log
Logical volume "lv_log" created
[root@localhost ~]# lvcreate -L 1.2G -n lv_data VolGroup_data
Rounding up size to full physical extent 1.20 GiB
Logical volume "lv_data" created

# 2 格式化分区（mkfs.ext4 /dev/卷组名/逻辑分区）
[root@localhost ~]# mkfs.ext4 /dev/VolGroup_log/lv_log
[root@localhost ~]# mkfs.ext4 /dev/VolGroup_data/lv_data


# 3 挂载分区（mount /dev/卷组名/逻辑分区 挂载点）
[root@localhost ~]# mkdir -p /da/log /da/data
[root@localhost ~]# mount /dev/VolGroup_log/lv_log /da/log
[root@localhost ~]# mount /dev/VolGroup_data/lv_data /da/data
```





卸载操作

```shell
# 1 卸载文件系统 umount

# 2 删除逻辑卷: lvremove  逻辑卷名

# 3 删除卷组：vgremove 卷组名

# 4 删除物理卷: pvremove /dev/sd*
```

```go
// https://github.com/openebs/lvm-localpv/blob/9e0ac5b4a8bacb9dc771d8d6c33293070df71507/pkg/lvm/lvm_util.go

func DestroyVolume(vol *apis.LVMVolume) error {
	// 判断存在性
	volExists, err := CheckVolumeExists(vol)
	if err != nil {
		return err
	}
	if !volExists {
		klog.Infof("lvm: volume (%s) doesn't exists, skipping its deletion", volume)
		return nil
	}
    // 清除文件系统
	err = removeVolumeFilesystem(vol)
	if err != nil {
		return err
	}

	// 删除 lv
	args := buildLVMDestroyArgs(vol)
	out, _, err := RunCommandSplit(LVRemove, args...)

	if err != nil {
		klog.Errorf(
			"lvm: could not destroy volume %v cmd %v error: %s", volume, args, string(out),
		)
		return err
	}

	klog.Infof("lvm: destroyed volume %s", volume)

	return nil
}

func removeVolumeFilesystem(lvmVolume *apis.LVMVolume) error {
	devicePath := filepath.Join(DevPath, lvmVolume.Spec.VolGroup, lvmVolume.Name)

	// wipefs erases the filesystem signature from the lvm volume
	// -a    wipe all magic strings
	// -f    force erasure
	// Command: wipefs -af /dev/lvmvg/volume1
	cleanCommand := exec.Command(BlockCleanerCommand, "-af", devicePath)
	output, err := cleanCommand.CombinedOutput()
	if err != nil {
		return errors.Wrapf(
			err,
			"failed to wipe filesystem on device path: %s resp: %s",
			devicePath,
			string(output),
		)
	}
	klog.V(4).Infof("Successfully wiped filesystem on device path: %s", devicePath)
	return nil
}
```

## RAID( Redundant Array of Independent Disks 独立硬盘冗余阵列）
旧称廉价磁盘冗余阵列（Redundant Array of Inexpensive Disks），简称磁盘阵列。其基本思想就是把多个相对便宜的硬盘组合起来，成为一个硬盘阵列组，使性能达到甚至超过一个价格昂贵、容量巨大的硬盘。


### raid 分类
#### raid 0


{{<figure src="./raid0.png#center" width=800px >}}

RAID 0亦称为带区集。它将两个以上的磁盘并联起来，成为一个大容量的磁盘。
在存放数据时，分段后分散存储在这些磁盘中，因为读写时都可以并行处理，所以在所有的级别中，RAID 0的速度是最快的。
但是RAID 0既没有冗余功能，也不具备容错能力，如果一个磁盘（物理）损坏，所有数据都会丢失，危险程度与JBOD（ Just a Bunch Of Disks）相当.

假设我们有2个磁盘驱动器，例如，如果我们将数据“TECMINT”写到逻辑卷中，“T”将被保存在第一盘中，“E”将保存在第二盘，'C'将被保存在第一盘，“M”将保存在第二盘，它会一直继续此循环过程。（LCTT 译注：实际上不可能按字节切片，是按数据块切片的。）


#### RAID 1

{{<figure src="./raid1.png#center" width=800px >}}

两组以上的N个磁盘相互作镜像，在一些多线程操作系统中能有很好的读取速度，理论上读取速度等于硬盘数量的倍数，与RAID 0相同。
另外写入速度有微小的降低。只要一个磁盘正常即可维持运作，可靠性最高。
其原理为在主硬盘上存放数据的同时也在镜像硬盘上写一样的数据。当主硬盘（物理）损坏时，镜像硬盘则代替主硬盘的工作。


#### 混合RAID: raid 10
{{<figure src="./featured.png#center" width=800px >}}
RAID 10 是组合 RAID 1 和 RAID 0 形成的.

### raid 操作 

```shell
# mdadm 使用
    创建模式：创建RAID设备
      -C 设备
           专用选项：
            -l：级别
            -n：设备个数
            -a {yes|no}：自动为其创建设备文件
            -c：chunk大小 2^n 默认为64k
            -x # : 指定空闲盘个数
    管理模式：管理，拆散，
      --add,--del ,--fail 
    监控模式：监控
         -F
    装配模式：换系统后，使用RAID
      -A 
    mdadm -A /dev/md1 /dev/sdb3 /dev/sdb2
     装配过程   
    增长模式：添加磁盘
    -G
-A, --assemble
              Assemble a pre-existing array.
-C, --create
              Create a new array.
-F, --follow, --monitor
              Select Monitor mode.
              
mdadm  -D  /dev/md#
     --detail   详细显示磁盘阵列的信息。
     
mdadm -f --fail --set 
mdadm /dev/md# --fail /dev/sda7


md - Multiple Device driver aka Linux Software RAID

RAID 0 
    2G
      4：512M
      2:1G
RAID 1/2
   2G：
      2:2G 
# 查看
mdadm --detail --scan --verbose
```


#### 创建raid
创建raid 0
```shell
# 1 安装 mdadm
yum install mdadm -y

# 2 确认硬盘数量
ls -l /dev | grep sd

# 3 确认硬盘没有被 raid 使用
mdadm --examine /dev/sd[b-c]

# 4 创建分区: parted 工具 

# 5  验证这两个驱动器是否正确定义 RAID
mdadm --examine /dev/sd[b-c]
mdadm --examine /dev/sd[b-c]1

# 6 创建 RAID md 设备: mdadm -C /dev/md0 -l raid0 -n 2 /dev/sd[b-c]1
mdadm --create /dev/md0 --level=stripe --raid-devices=2 /dev/sd[b-c]1

# 7 查看 RAID 级别，设备和阵列的使用状态
cat /proc/mdstat

# 8 保存 RAID 配置 mdadm -E -s -v >> /etc/mdadm.conf
mdadm --detail --scan --verbose >> /etc/mdadm.conf  
```



#### 卸载 raid
```shell
# 1 卸载挂载中的设备
umount /dev/md0

# 2 停止 raid 服务
mdadm --stop /dev/md0


# 3 卸载 raid10 中所有磁盘信息
mdadm --misc --zero-superblock /dev/sdb
mdadm --misc --zero-superblock /dev/sdc
mdadm --misc --zero-superblock /dev/sdd
mdadm --misc --zero-superblock /dev/sde

# 4 删除 raid 的配置文件
rm /etc/mdadm.conf

# 5 清除开机挂载信息 /etc/fstab
```


## 参考

- https://www.diskinternals.com/raid-recovery/how-to-remove-software-raid-with-mdadm/
- [LVM的基本概念和部署](http://xintq.net/2014/07/30/LVM%E7%9A%84%E5%9F%BA%E6%9C%AC%E6%A6%82%E5%BF%B5%E5%92%8C%E9%83%A8%E7%BD%B2/)
- [fdisk,gdisk,parted 三种分区工具比较](https://www.cnblogs.com/zhaojiedi1992/p/zhaojiedi_linux_039_fdisk_gdisk_parted.html)
- [LVM管理](https://www.cnblogs.com/diantong/p/10554831.html)
- [RAID及mdadm命令](https://cloud.tencent.com/developer/article/1108103)
- [使用 mdadm 工具创建软 RAID 0 ](https://golinux.gitbooks.io/raid/content/chapter2.html)
