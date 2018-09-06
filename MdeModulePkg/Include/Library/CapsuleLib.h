/** @file
  The definitions needed for Capusle on Disk.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under 
the terms and conditions of the BSD License that accompanies this distribution.  
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.                                            

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CAPSULE_LIB_H__
#define __CAPSULE_LIB_H__

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

//
// BOOLEAN Variable to save the total size of all Capsule On Disk during relocation
//
#define COD_RELOCATION_INFO_VAR_NAME   L"CodRelocationInfo"

/**
  The firmware checks whether the capsule image is supported 
  by the CapsuleGuid in CapsuleHeader or if there is other specific information in 
  the capsule image.

  Caution: This function may receive untrusted input.

  @param  CapsuleHeader    Pointer to the UEFI capsule image to be checked.
  
  @retval EFI_SUCESS       Input capsule is supported by firmware.
  @retval EFI_UNSUPPORTED  Input capsule is not supported by the firmware.

**/
EFI_STATUS
EFIAPI
SupportCapsuleImage (
  IN EFI_CAPSULE_HEADER *CapsuleHeader
  );

/**
  The firmware-specific implementation processes the capsule image
  if it recognized the format of this capsule image.

  Caution: This function may receive untrusted input.

  @param  CapsuleHeader    Pointer to the UEFI capsule image to be processed. 
   
  @retval EFI_SUCESS       Capsule Image processed successfully. 
  @retval EFI_UNSUPPORTED  Capsule image is not supported by the firmware.

**/
EFI_STATUS
EFIAPI
ProcessCapsuleImage (
  IN EFI_CAPSULE_HEADER *CapsuleHeader
  );

/**
  The firmware-specific implementation processes the capsule image
  if it recognized the format of this capsule image.

  Caution: This function may receive untrusted input.

  @param  CapsuleHeader    Pointer to the UEFI capsule image to be processed. 
  @param  CapFileName    Name of the the UEFI capsule image to be processed. Only used when Capsule from File 

  @retval EFI_SUCESS       Capsule Image processed successfully. 
  @retval EFI_UNSUPPORTED  Capsule image is not supported by the firmware.

**/
EFI_STATUS
EFIAPI
ProcessCapsuleImageEx (
  IN EFI_CAPSULE_HEADER *CapsuleHeader,
  IN CHAR16             *CapFileName
  );

/**
  This routine is called to process capsules.

  Caution: This function may receive untrusted input.

  The capsules reported in EFI_HOB_UEFI_CAPSULE are processed.
  If there is no EFI_HOB_UEFI_CAPSULE, this routine does nothing.

  This routine should be called twice in BDS.
  1) The first call must be before EndOfDxe. The system capsules is processed.
     If device capsule FMP protocols are exposted at this time and device FMP
     capsule has zero EmbeddedDriverCount, the device capsules are processed.
     Each individual capsule result is recorded in capsule record variable.
     System may reset in this function, if reset is required by capsule and
     all capsules are processed.
     If not all capsules are processed, reset will be defered to second call.

  2) The second call must be after EndOfDxe and after ConnectAll, so that all
     device capsule FMP protocols are exposed.
     The system capsules are skipped. If the device capsules are NOT processed
     in first call, they are processed here.
     Each individual capsule result is recorded in capsule record variable.
     System may reset in this function, if reset is required by capsule
     processed in first call and second call.

  @retval EFI_SUCCESS             There is no error when processing capsules.
  @retval EFI_OUT_OF_RESOURCES    No enough resource to process capsules.

**/
EFI_STATUS
EFIAPI
ProcessCapsules (
  VOID
  );

/**
  This routine is called to check if CapsuleOnDisk flag in OsIndications Variable
  is enabled.

  @retval TRUE     Flag is enabled
          FALSE    Flag is not enabled

**/
BOOLEAN
CoDCheckCapsuleOnDiskFlag(
  VOID
  );


/**
  This routine is called to clear CapsuleOnDisk flags including OsIndications and BootNext variable

  @retval EFI_SUCCESS   All Capsule On Disk flags are cleared

**/
EFI_STATUS
CoDClearCapsuleOnDiskFlag(
  VOID
  );

/**

  This routine is called to clear CapsuleOnDisk flags including OsIndications and BootNext variable

  @retval EFI_SUCCESS   Capsule On Disk flags are cleared

**/
EFI_STATUS
EFIAPI
CoDCheckCapsuleRelocationInfo(
  OUT BOOLEAN *CapsuleRelocInfo
  );

/**
  This routine is called to clear CapsuleOnDisk Relocation Info variable.
  Total Capsule On Disk length is recorded in this variable

  @retval EFI_SUCCESS   Capsule On Disk flags are cleared

**/
EFI_STATUS
CoDClearCapsuleRelocationInfo(
  VOID
  );

/**
  Relocate Capsule on Disk from EFI system partition to a platform-specific NV storage device
  with BlockIo protocol.  Relocation device path, identified by PcdCodRelocationDevPath, must
  be a full device path.
  Device enumeration like USB costs time, user can input MaxRetry to tell function to retry.
  Function will stall 100ms between each retry.

  Side Effects:
    Content corruption. Block IO write directly touches low level write. Orignal partitions, file systems 
    of the relocation device will be corrupted.

  @retval TRUE   Capsule on Disk images are sucessfully relocated to the platform-specific device..

**/
EFI_STATUS
EFIAPI
CoDRelocateCapsule(
  UINTN     MaxRetry
  );

/**
  The function is called by Get Relocate Capsule on Disk from EFI system partition to a platform-specific
  NV storage device producing BlockIo protocol.  Relocation device path is identified by PcdCodRelocationDevPath.
  The connection logic in this function assumes it is a full device path.

  Caution:
    Retrieve relocated capsule is done by TCB. Therefore, the relocation device connection happens within TCB.
    TCB must be immutable and attack surface must be small. Partition and FAT driver are not included in TCB.
    Platform should configure FULL physical device path without logic Partition device path node.
    A example is 
      PciRoot(0x0) \ Pci(0x1D,0x0) \ USB(0x0,0x0) \ USB(0x3, 0x0)

  @retval TRUE   All capsule images are processed.

**/
EFI_STATUS
EFIAPI
CoDRetrieveRelocatedCapsule (
  IN  UINTN                MaxRetry,
  OUT EFI_PHYSICAL_ADDRESS **CapsuleBufPtr,
  OUT UINTN                *CapsuleNum
  );


#endif
