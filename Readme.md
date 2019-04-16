
# Introduction

This branch is used to develop the **Capsule-On-Disk** feature.
The branch owner: Chao Zhang < [chao.b.zhang@intel.com](mailto:chao.b.zhang@intel.com) >, Wei Xu < [wei6.xu@intel.com](mailto:wei6.xu@intel.com) >

# Feature Summary

Traditionally capsule image is delivered to BIOS in persistent memory across system reset, but not all platforms support or function well across memory persistent reset. To solve this problem, **Capsule-On-Disk** delivers capsule images through EFI system partition on peripheral storage device. For security reasons, Design is composed of 2 solutions. 
- **Solution A)** - Load the image out of TCB and rely on Capsule-In-RAM to deliver Capsule-On-Disk. 
- **Solution B)** - Relocate capsule image outside TCB. And leverage existing storage stack in PEI to load all capsule on disk images. Solution B) has bigger TCB but can work without Capsule-In-RAM support

>User can test this feature with **CapsuleApp** in **MdeModulePkg**. It has been updated to support Capsule on Disk since **2019 Q1 stable release**.

Brief working flow of  **Capsule-On-Disk**:
```
1. Store capsule images into \EFI\Capsules\ folder on EFI system partition.
2. Set EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED flag in L"OsIndications".
3. Reboot system.
4. Get all capsule images from \EFI\Capsules\ after TCB, relocated them to root direcotry of a platform-specific NV storage device with BlockIo protocol.
5. Reboot system.
6. Load capsule imaages from the root direcotry in TCB, and build CV hobs
```

## Related Modules

The following modules are related to **Capsule-On-Disk**.
```
MdeModulePkg\Library\DxeCapsuleLibFmp\DxeCapsuleLib.inf
MdeModulePkg\Universal\CapsuleOnDiskLoadPei\CapsuleOnDiskLoadPei.inf
```

# Promote to edk2 Trunk
 
If a subset feature or a bug fix in this staging branch could meet below requirement, it could be promoted to edk2 trunk and removed from this staging branch:

- Meet all edk2 required quality criteria.
- Ready for product integration.

# Time Line

|Time| Event |
|---|---|
|2019 Q2| Exit Staging|


# Related Materials

UEFI Specification - http://uefi.org/specifications