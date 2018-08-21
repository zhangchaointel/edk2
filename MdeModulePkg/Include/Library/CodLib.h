/** @file

  This library class defines a set of interfaces to process Capsules from Disk.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under 
the terms and conditions of the BSD License that accompanies this distribution.  
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.                                            

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __COD_LIB_H__
#define __COD_LIB_H__

#include <Guid/FileInfo.h>

typedef struct {
  //
  // image address.
  //
  VOID             *ImageAddress;
  //
  // The file info of the image comes from.
  //  if FileInfo == NULL. means image does not come from file
  //
  EFI_FILE_INFO    *FileInfo;
} IMAGE_INFO;

#define COD_RELOCATION_INFO_VAR_NAME   L"CodRelocationInfo"

BOOLEAN
CodLibCheckCapsuleOnDiskFlag(
  VOID
  );


/*
Reset OsIndication File Capsule Delivery Supported Flag
and clear the boot next variable.
*/
EFI_STATUS
CoDLibClearCapsuleOnDiskFlag(
  VOID
  );


EFI_STATUS
EFIAPI
CodLibCheckCapsuleRelocationInfo(
  OUT UINT64 *RelocTotalSize
  );


/*
Reset OsIndication File Capsule Delivery Supported Flag
and clear the boot next variable.
*/
EFI_STATUS
CoDLibClearCapsuleRelocationInfo(
  VOID
  );

EFI_STATUS
EFIAPI
CodLibRelocateCapsule(
  UINTN     MaxRetry
  );

EFI_STATUS
EFIAPI
CodLibRetrieveRelocatedCapsule (
  IN  UINTN                MaxRetry,
  OUT EFI_PHYSICAL_ADDRESS **CapsuleBufPtr,
  OUT UINTN                *CapsuleNum
  );


#endif
