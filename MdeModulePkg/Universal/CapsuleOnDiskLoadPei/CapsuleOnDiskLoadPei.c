/** @file
  Recovery module.

  Caution: This module requires additional review when modified.
  This module will have external input - Capsule-on-Disk Temp Relocation image.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  RetrieveRelocatedCapsule() will receive untrusted input and do basic validation.

Copyright (c) 2016 - 2019, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

//
// The package level header files this module uses
//
#include <Uefi.h>
#include <PiPei.h>

//
// The protocols, PPI and GUID defintions for this module
//
#include <Ppi/MasterBootMode.h>
#include <Ppi/FirmwareVolumeInfo.h>
#include <Ppi/ReadOnlyVariable2.h>
#include <Ppi/Capsule.h>
#include <Ppi/CapsuleOnDisk.h>
#include <Ppi/DeviceRecoveryModule.h>

#include <Guid/FirmwareFileSystem2.h>
//
// The Library classes this module consumes
//
#include <Library/DebugLib.h>
#include <Library/PeimEntryPoint.h>
#include <Library/PeiServicesLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/CapsuleLib.h>

/**
  Loads a DXE capsule from some media into memory and updates the HOB table
  with the DXE firmware volume information.

  @param[in]  PeiServices   General-purpose services that are available to every PEIM.
  @param[in]  This          Indicates the EFI_PEI_RECOVERY_MODULE_PPI instance.

  @retval EFI_SUCCESS        The capsule was loaded correctly.
  @retval EFI_DEVICE_ERROR   A device error occurred.
  @retval EFI_NOT_FOUND      A recovery DXE capsule cannot be found.

**/
EFI_STATUS
EFIAPI
LoadCapsuleOnDisk (
  IN EFI_PEI_SERVICES              **PeiServices,
  IN EFI_PEI_CAPSULE_ON_DISK_PPI   *This
  );

EFI_PEI_CAPSULE_ON_DISK_PPI mCapsuleOnDiskPpi = {
  LoadCapsuleOnDisk
};

EFI_PEI_PPI_DESCRIPTOR mCapsuleOnDiskPpiList = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEdkiiPeiCapsuleOnDiskPpiGuid,
  &mCapsuleOnDiskPpi
};

/**
  Determine if capsule comes from memory by checking Capsule PPI.

  @param[in]  PeiServices General purpose services available to every PEIM.

  @retval TRUE   Capsule comes from memory.
  @retval FALSE  No capsule comes from memory.

**/
STATIC
BOOLEAN
CheckCapsuleFromRam (
  IN CONST EFI_PEI_SERVICES          **PeiServices
  )
{
  EFI_STATUS              Status;
  PEI_CAPSULE_PPI         *Capsule;

  Status = PeiServicesLocatePpi (
             &gPeiCapsulePpiGuid,
             0,
             NULL,
             (VOID **) &Capsule
             );
  if (!EFI_ERROR(Status)) {
    Status = Capsule->CheckCapsuleUpdate ((EFI_PEI_SERVICES **)PeiServices);
    if (!EFI_ERROR(Status)) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Determine if it is a Capsule On Disk mode.

  @retval TRUE         Capsule On Disk mode.
  @retval FALSE        Not capsule On Disk mode.

**/
BOOLEAN
IsCapsuleOnDiskMode (
  VOID
  )
{
  EFI_STATUS                      Status;
  UINTN                           Size;
  EFI_PEI_READ_ONLY_VARIABLE2_PPI *PPIVariableServices;
  BOOLEAN                         CodRelocInfo;

  Status = PeiServicesLocatePpi (
             &gEfiPeiReadOnlyVariable2PpiGuid,
             0,
             NULL,
             (VOID **) &PPIVariableServices
             );
  ASSERT_EFI_ERROR (Status);

  Size = sizeof (BOOLEAN);
  Status = PPIVariableServices->GetVariable (
                                  PPIVariableServices,
                                  COD_RELOCATION_INFO_VAR_NAME,
                                  &gEfiCapsuleVendorGuid,
                                  NULL,
                                  &Size,
                                  &CodRelocInfo
                                  );

  if (EFI_ERROR (Status) || Size != sizeof(BOOLEAN) || CodRelocInfo != TRUE) {
    DEBUG (( EFI_D_ERROR, "Error Get CodRelocationInfo variable %r!\n", Status));
    return FALSE;
  }

  return TRUE;
}

/**
  Gets capsule images and capsule names from relocated capsule buffer.
  Create Capsule hob & Capsule Name Str Hob for each Capsule.

  @param[in]  Buffer pointer to the relocated capsule.
  @param[in]  Total size of the relocated capsule.

  @retval EFI_SUCCESS     Succeed to get capsules and create hob.
  @retval Others          Fail to get capsules and create hob.

**/
EFI_STATUS
EFIAPI
RetrieveRelocatedCapsule (
  IN UINT8                *RelocCapsuleBuf,
  IN UINTN                RelocCapsuleTotalSize
  )
{
  EFI_STATUS               Status;
  UINTN                    Index;
  UINT8                    *CapsuleDataBufEnd;
  UINT8                    *CapsuleNameBufEnd;
  UINT8                    *CapsulePtr;
  UINT8                    *CapsuleNamePtr;
  UINT32                   CapsuleSize;
  UINT32                   CapsuleNameSize;
  UINT64                   TotalImageSize;
  UINT64                   TotalImageNameSize;

  //
  // Temp file contains at least 1 capsule & 2 UINT64
  //
  if (RelocCapsuleTotalSize < sizeof(UINT64) * 2 + sizeof(EFI_CAPSULE_HEADER)) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(&TotalImageSize, RelocCapsuleBuf, sizeof(UINT64));
  CopyMem(&TotalImageNameSize, RelocCapsuleBuf + sizeof(UINT64), sizeof(UINT64));

  DEBUG ((DEBUG_INFO, "ProcessRelocatedCapsule CapsuleBuf %x TotalCapSize %lx TotalNameSize %lx\n", 
                      RelocCapsuleBuf, TotalImageSize, TotalImageNameSize));

  RelocCapsuleBuf += sizeof(UINT64) * 2;

  //
  // Overflow check
  //
  if (MAX_ADDRESS - TotalImageNameSize <= sizeof(UINT64) * 2 ||
      MAX_ADDRESS - (UINTN)TotalImageSize <= (UINTN)TotalImageNameSize + sizeof(UINT64) * 2 ||
      RelocCapsuleTotalSize != (UINTN)(TotalImageSize  + TotalImageNameSize + sizeof(UINT64) * 2) ||
      (MAX_ADDRESS - (PHYSICAL_ADDRESS)RelocCapsuleBuf) <= (UINTN)TotalImageSize) {
    return EFI_INVALID_PARAMETER;
  }

  CapsuleDataBufEnd = RelocCapsuleBuf + TotalImageSize;

  if ((MAX_ADDRESS - (PHYSICAL_ADDRESS)CapsuleDataBufEnd) <= (UINTN)TotalImageNameSize) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // TempCapsule file integrity Check to ensure no data corruption in NV Var & Relocation storage
  //   1. Integrity check over Capsule Header
  //   2. Integrity check over Capsule File Name
  //
  CapsulePtr = RelocCapsuleBuf;
  if (((UINTN)CapsuleDataBufEnd & 0x01) != 0) {
    CapsuleNamePtr = AllocatePages(EFI_SIZE_TO_PAGES((UINTN)TotalImageNameSize));
    if (CapsuleNamePtr == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(CapsuleNamePtr, CapsuleDataBufEnd, (UINTN)TotalImageNameSize);
  } else {
    CapsuleNamePtr  = CapsuleDataBufEnd;
  }
  CapsuleNameBufEnd = CapsuleNamePtr + TotalImageNameSize;

  while (CapsulePtr < CapsuleDataBufEnd && CapsuleNamePtr < CapsuleNameBufEnd) {
    CapsuleNameSize = StrnSizeS((CONST CHAR16 *)CapsuleNamePtr, (UINTN)TotalImageNameSize);
    if ((CapsuleDataBufEnd - CapsulePtr) < sizeof(EFI_CAPSULE_HEADER) ||
        (MAX_ADDRESS - (PHYSICAL_ADDRESS)CapsulePtr) < ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize ||
        CapsuleNameSize == 0) {
      break;
    }
    CapsulePtr     += ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize;
    CapsuleNamePtr += CapsuleNameSize;
  }

  if (CapsulePtr != CapsuleDataBufEnd || CapsuleNamePtr != CapsuleNameBufEnd) {
    Status = EFI_INVALID_PARAMETER;
    goto EXIT;
  }

  //
  // Re-iterate the capsule buffer to create Capsule hob & Capsule Name Str Hob for each Capsule saved in relocated capsule file
  //
  CapsulePtr     = RelocCapsuleBuf;
  CapsuleNamePtr = CapsuleNameBufEnd - (UINTN)TotalImageNameSize;
  Index          = 0;
  while (CapsulePtr < CapsuleDataBufEnd && CapsuleNamePtr < CapsuleNameBufEnd) {

    CapsuleNameSize = StrnSizeS((CONST CHAR16 *)CapsuleNamePtr, (UINTN)TotalImageNameSize);
    CapsuleSize     = ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize;

    BuildCvHob ((EFI_PHYSICAL_ADDRESS)(UINTN)CapsulePtr, CapsuleSize);
    BuildGuidDataHob(&gEdkiiCapsuleOnDiskNameGuid, CapsuleNamePtr, CapsuleNameSize);

    DEBUG((DEBUG_INFO, "0x%x Capsule %S found in Capsule on Disk relocation file\n", Index, CapsuleNamePtr));
    DEBUG((DEBUG_INFO, "Capsule saved in address %x size %x\n", CapsulePtr, CapsuleSize));

    CapsulePtr     += CapsuleSize;
    CapsuleNamePtr += CapsuleNameSize;
    Index++;
  }

EXIT:

  return Status;
}

/**
  Recovery module entrypoint

  @param[in] FileHandle   Handle of the file being invoked.
  @param[in] PeiServices  Describes the list of possible PEI Services.

  @return EFI_SUCCESS Recovery module is initialized.
**/
EFI_STATUS
EFIAPI
InitializeCapsuleOnDiskLoad (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS  Status;
  UINTN       BootMode;
  UINTN       FileNameSize;

  BootMode = GetBootModeHob();
  ASSERT(BootMode == BOOT_ON_FLASH_UPDATE);

  //
  // If there are capsules provisioned in memory, quit.
  // Only one capsule resource is accept, CapsuleOnRam's priority is higher than CapsuleOnDisk.
  //
  if (CheckCapsuleFromRam(PeiServices)) {
    DEBUG((DEBUG_ERROR, "Capsule On Memory Detected! Quit.\n"));
    return EFI_ABORTED;
  }

  DEBUG_CODE (
   VOID *CapsuleOnDiskModePpi;

  if (!IsCapsuleOnDiskMode()){
    return EFI_NOT_FOUND;
  }

  //
  // Check Capsule On Disk Relocation flag. If exists, load capsule & create Capsule Hob
  //
  Status = PeiServicesLocatePpi (
             &gEfiPeiBootInCapsuleOnDiskModePpiGuid,
             0,
             NULL,
             (VOID **)&CapsuleOnDiskModePpi
             );
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "Locate CapsuleOnDiskModePpi error %x\n", Status));
      return Status;
    }
  );

  Status = (**PeiServices).InstallPpi (PeiServices, &mCapsuleOnDiskPpiList);
  ASSERT_EFI_ERROR (Status);

  FileNameSize = PcdGetSize (PcdCoDRelocationFileName);
  Status = PcdSetPtrS (PcdRecoveryFileName, &FileNameSize, PcdGetPtr(PcdCoDRelocationFileName));
  ASSERT_EFI_ERROR (Status);

  return Status;
}

/**
  Loads a DXE capsule from some media into memory and updates the HOB table
  with the DXE firmware volume information.

  @param[in]  PeiServices   General-purpose services that are available to every PEIM.
  @param[in]  This          Indicates the EFI_PEI_RECOVERY_MODULE_PPI instance.

  @retval EFI_SUCCESS        The capsule was loaded correctly.
  @retval EFI_DEVICE_ERROR   A device error occurred.
  @retval EFI_NOT_FOUND      A recovery DXE capsule cannot be found.

**/
EFI_STATUS
EFIAPI
LoadCapsuleOnDisk (
  IN EFI_PEI_SERVICES                     **PeiServices,
  IN EFI_PEI_CAPSULE_ON_DISK_PPI          *This
  )
{
  EFI_STATUS                          Status;
  EFI_PEI_DEVICE_RECOVERY_MODULE_PPI  *DeviceRecoveryPpi;
  UINTN                               NumberRecoveryCapsules;
  UINTN                               Instance;
  UINTN                               CapsuleInstance;
  UINTN                               CapsuleSize;
  EFI_GUID                            CapsuleType;
  VOID                                *CapsuleBuffer;

  DEBUG((DEBUG_INFO | DEBUG_LOAD, "Load Capsule On Disk Entry\n"));

  for (Instance = 0; ; Instance++) {
    Status = PeiServicesLocatePpi (
               &gEfiPeiDeviceRecoveryModulePpiGuid,
               Instance,
               NULL,
               (VOID **)&DeviceRecoveryPpi
               );
    DEBUG ((DEBUG_ERROR, "LoadCapsuleOnDisk - LocateRecoveryPpi (%d) - %r\n", Instance, Status));
    if (EFI_ERROR (Status)) {
      break;
    }
    NumberRecoveryCapsules = 0;
    Status = DeviceRecoveryPpi->GetNumberRecoveryCapsules (
                                  (EFI_PEI_SERVICES **)PeiServices,
                                  DeviceRecoveryPpi,
                                  &NumberRecoveryCapsules
                                  );
    DEBUG ((DEBUG_ERROR, "LoadCapsuleOnDisk - GetNumberRecoveryCapsules (%d) - %r\n", NumberRecoveryCapsules, Status));
    if (EFI_ERROR (Status)) {
      continue;
    }

    for (CapsuleInstance = 1; CapsuleInstance <= NumberRecoveryCapsules; CapsuleInstance++) {
      CapsuleSize = 0;
      Status = DeviceRecoveryPpi->GetRecoveryCapsuleInfo (
                                    (EFI_PEI_SERVICES **)PeiServices,
                                    DeviceRecoveryPpi,
                                    FeaturePcdGet(PcdFrameworkCompatibilitySupport) ? CapsuleInstance - 1 : CapsuleInstance,
                                    &CapsuleSize,
                                    &CapsuleType
                                    );
      DEBUG ((DEBUG_ERROR, "LoadCapsuleOnDisk - GetRecoveryCapsuleInfo (%d - %x) - %r\n", CapsuleInstance, CapsuleSize, Status));
      if (EFI_ERROR (Status)) {
        break;
      }

      //
      // Allocate the memory so that it gets preserved into DXE. 
      // Capsule is special because it may need to populate to system table
      //
      CapsuleBuffer = AllocateRuntimePages (EFI_SIZE_TO_PAGES (CapsuleSize));

      if (CapsuleBuffer == NULL) {
        DEBUG ((DEBUG_ERROR, "LoadCapsuleOnDisk - AllocateRuntimePages fail\n"));
        continue;
      }

      Status = DeviceRecoveryPpi->LoadRecoveryCapsule (
                                    (EFI_PEI_SERVICES **)PeiServices,
                                    DeviceRecoveryPpi,
                                    FeaturePcdGet(PcdFrameworkCompatibilitySupport) ? CapsuleInstance - 1 : CapsuleInstance,
                                    CapsuleBuffer
                                    );
      DEBUG ((DEBUG_ERROR, "LoadCapsuleOnDisk - LoadRecoveryCapsule (%d) - %r\n", CapsuleInstance, Status));
      if (EFI_ERROR (Status)) {
        FreePages (CapsuleBuffer, EFI_SIZE_TO_PAGES(CapsuleSize));
        break;
      }

      //
      // Capsule Update Mode, Split relocated Capsule buffer into different capsule vehical hobs.
      //
      Status = RetrieveRelocatedCapsule(CapsuleBuffer, CapsuleSize);

      break;
    }

    return Status;
  }

  //
  // Any attack against GPT, Relocation Info Variable or temp relocation file will result in no Capsule HOB and return EFI_NOT_FOUND.
  // After flow to DXE phase. since no capsule hob is detected. Platform will clear Info flag and force restart.
  // No volunerability will be exposed 
  //

  return EFI_NOT_FOUND;
}
