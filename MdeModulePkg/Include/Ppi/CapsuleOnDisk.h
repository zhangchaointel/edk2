/** @file
  This file declares Capsule On Disk PPI.  This PPI is used to find and load the
  capsule on files that are relocated into a temp file under rootdir.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PEI_CAPSULE_ON_DISK_PPI_H__
#define __PEI_CAPSULE_ON_DISK_PPI_H__

#define EFI_PEI_CAPSULE_ON_DISK_PPI_GUID \
  { \
    0x71a9ea61, 0x5a35, 0x4a5d, {0xac, 0xef, 0x9c, 0xf8, 0x6d, 0x6d, 0x67, 0xe0 } \
  }

typedef struct _EFI_PEI_CAPSULE_ON_DISK_PPI EFI_PEI_CAPSULE_ON_DISK_PPI;

/**
  Loads a DXE capsule from some media into memory and updates the HOB table
  with the DXE firmware volume information.

  @param  PeiServices   General-purpose services that are available to every PEIM.
  @param  This          Indicates the EFI_PEI_RECOVERY_MODULE_PPI instance.

  @retval EFI_SUCCESS        The capsule was loaded correctly.
  @retval EFI_DEVICE_ERROR   A device error occurred.
  @retval EFI_NOT_FOUND      A recovery DXE capsule cannot be found.

**/
typedef
EFI_STATUS
(EFIAPI *EFI_PEI_LOAD_CAPSULE_ON_DISK)(
  IN EFI_PEI_SERVICES             **PeiServices,
  IN EFI_PEI_CAPSULE_ON_DISK_PPI  *This
  );

///
///  Finds and loads the recovery files.
///
struct _EFI_PEI_CAPSULE_ON_DISK_PPI {
  EFI_PEI_LOAD_CAPSULE_ON_DISK LoadCapsuleOnDisk;  ///< Loads a DXE binary capsule into memory.
};

extern EFI_GUID gEdkiiPeiCapsuleOnDiskPpiGuid;

#endif
