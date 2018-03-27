/** @file
  The implementation Loading Capusle on Disk into Memory.

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
//#include <Guid/CapsuleVendor.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileSystemInfo.h>
#include <Protocol/BlockIo.h>
#include <Library/CapsuleLib.h>
#include <Library/CoDLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>

CHAR16 *mDirName = L"\\efi\\UpdateCapsule";

#define EFI_CAPSULE_VARIABLE_NAME L"CapsuleUpdateData"
UINT32
EFIAPI
GetBootTypeFromDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL     *DevicePath
  );

/*
Reset OsIndication File Capsule Delivery Supported Flag
and clear the boot next variable.
*/
EFI_STATUS
CoDClearCapsuleFlags(
    VOID
  )
{
  EFI_STATUS            Status;
  UINT64                OsIndication;
  UINTN                 DataSize;

  // Reset OsIndication File Capsule Delivery Supported Flag
  OsIndication = 0;
  DataSize = sizeof(UINT64);
  Status = gRT->GetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &DataSize,
                  &OsIndication
                  );
  if (EFI_ERROR(Status)) {
    OsIndication = 0;
  }
  OsIndication &= ~((UINT64)EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED);
  Status = gRT->SetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  sizeof(UINT64),
                  &OsIndication
                );

  // Clear the boot next variable
  Status = gRT->SetVariable (
        L"BootNext",
        &gEfiGlobalVariableGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
        0,
        NULL
        );

  return EFI_SUCCESS;
}


/**
Auto detect Capsule file and update Boot Partition regions.

@retval EFI_SUCCESS.            - Opertion is successful.
@retval EFI_OUT_OF_RESOURCES    - No enough buffer to allocate.
@retval EFI_ERROR.              - Internal error when update Capsule
**/
EFI_STATUS
LoadCapsuleFromDisk(
  VOID
  )
{
  EFI_STATUS            Status;
  UINT8                 *FileBuffer = NULL;
  EFI_CAPSULE_HEADER    *ech[1];
  EFI_PHYSICAL_ADDRESS  sc = (EFI_PHYSICAL_ADDRESS)0;

  DEBUG((EFI_D_INFO, "Capsule on Disk Update Entry Point...\n"));

  Status = GetCapsuleInfo(&FileBuffer);

  if (!EFI_ERROR(Status)) {
    ech[0] = (EFI_CAPSULE_HEADER *)FileBuffer;
    DEBUG((EFI_D_INFO, "Pass Capsule image to UpdateCapsule service.\n"));
    Status = gRT->UpdateCapsule(ech, 1, sc);
  }

  //
  // If capsule update returns, free buffer and reset.
  //
  DEBUG((EFI_D_INFO, "Leaving LoadCapsuleFromDisk\n"));
  FreePool(FileBuffer);
  gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);

  return Status;
}

/**
Get Capsule information

@param[in]  FileName            - File name of Capsule binary
@param[out] CapsuleBuffer          - Return buffer pointer of Capsule binary
@param[out] CapsuleSize            - Capsule binary size

@retval EFI_SUCCESS             - Read Capsule information successfully
@retval EFI_OUT_OF_RESOURCES    - No enough buffer to allocate.
@retval EFI_ABORTED             - Fail to read Capsule information
@retval Others                  - Internal error when read Capsule information
**/
EFI_STATUS
GetCapsuleInfo(
  OUT VOID    **CapsuleBuffer
  )
{
  EFI_STATUS                          Status = EFI_SUCCESS;
  EFI_STATUS                          FindStatus = EFI_SUCCESS;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *Fs;
  EFI_FILE                            *Root;
  EFI_FILE                            *FileHandle = NULL;
  UINTN                               FileSize = 0;
  UINT8                               *FileBuffer = NULL;
  EFI_FILE_PROTOCOL                   *DirHandle = NULL;
  UINTN                               Index = 0;
  EFI_HANDLE                          *HandleArray = NULL;
  UINTN                               HandleArrayCount;
  EFI_PHYSICAL_ADDRESS                *Address;
  EFI_FILE_INFO                       *FileInfo;
  BOOLEAN                             NoFile = FALSE;
  UINTN                               *CapsuleSize = NULL;
  BOOLEAN                             FoundFile = FALSE;

  DEBUG((EFI_D_ERROR, "GetCapsuleInfo\n"));

  DEBUG((EFI_D_ERROR, "Find all simple file system protocols that may have been found\n"));
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleArrayCount, &HandleArray);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Unable to locate any valid file systems.\n"));
    return Status;
  }
  DEBUG((EFI_D_INFO, "Simple File System Count is: %d\n", HandleArrayCount));

  //
  // Search all system partitions
  //
  for (Index = 0; Index < HandleArrayCount; Index++) {
    //
    // Get the SFS protocol from the handle
    //
    Status = gBS->HandleProtocol(HandleArray[Index], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "Cannot locate SFS protocol. Status = %r\n", Status));
      continue;
    }

    //
    // Open the root directory, get EFI_FILE_PROTOCOL
    //
    DEBUG((EFI_D_ERROR, "Going to try to open the  volume\n"));
    Status = Fs->OpenVolume(Fs, &Root);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "Cannot open volume. Status = %r\n", Status));
      continue;
    }

    DEBUG((EFI_D_ERROR, "Going to try to open the directory\n"));
    Status = Root->Open(Root, &DirHandle, mDirName, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_INFO, "Cannot open directory: %s. Status = %r\n", mDirName, Status));
      continue;
    } else {
      DEBUG((EFI_D_ERROR, "Did dir open Status = %r\n", Status));
    }

    //
    // Handle "." and ".." in directory
    //
    DEBUG((EFI_D_ERROR, "Going to find a file\n"));
    Status = FileHandleFindFirstFile(DirHandle, &FileInfo);  // "."
    FindStatus = FileHandleFindNextFile(DirHandle, FileInfo, &NoFile); // ".."
    if (!FindStatus) {
      DEBUG((EFI_D_INFO, "Found %s\n", FileInfo->FileName));
    }

    //
    // Find potential capsule files (if any)
    //
    while (FindStatus == EFI_SUCCESS && NoFile == FALSE) {
      DEBUG((EFI_D_ERROR, "Looking for capsule files...\n"));
      FindStatus = FileHandleFindNextFile(DirHandle, FileInfo, &NoFile);

      //
      // Break, if the last file is detected
      //
      if (NoFile == TRUE) {
        DEBUG((EFI_D_INFO, "Found last file in directory.\n"));
        break;
      }

      //
      // Handle a file
      //
      if (!FindStatus && NoFile==FALSE) {
        DEBUG((EFI_D_INFO, "Found %s\n", FileInfo->FileName));
        //
        // A file is found
        //
        Status = Root->Open(DirHandle, &FileHandle, FileInfo->FileName, EFI_FILE_MODE_READ , 0); //We never close DirHandle
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_INFO, "Cannot open file: %s. Status = %r\n", FileInfo->FileName, Status));
          continue;
        }

        if (FileHandle == NULL) {
          Status = EFI_UNSUPPORTED;
          DEBUG((EFI_D_ERROR, "Failed to open root dir on partition for reading. Stautus = %r\n", Status));
          continue;
        }

        Status = FileHandleGetSize(FileHandle, (UINT64*)&FileSize);
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "GetSize failed. Status = %r\n", Status));
          FileHandleClose(FileHandle);
          FileHandle = NULL;
          continue;
        }
        DEBUG((EFI_D_INFO, "File Size: 0x%08x\r\n", FileSize));

        //Size = FileSize;
        Status = gBS->AllocatePool(
          EfiBootServicesData,
          FileSize,
          (VOID **) &Address);

        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "Allocate memory for file buffer failed.\n"));
          FileHandleClose(FileHandle);
          FileHandle = NULL;
          return EFI_OUT_OF_RESOURCES;
        }

        FileBuffer = (UINT8 *)(UINTN)Address;
        Status = FileHandleRead(FileHandle, &FileSize, FileBuffer);
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "File read failed. Status = %r\n", Status));
          FileHandleClose(FileHandle);
          FileHandle = NULL;
          FreePool(FileBuffer);
          FileBuffer = NULL;
          continue;
        }

        // Attempt to delete the file!
        // NOTE: If successful FileHandle will be closed and the file deleted!
        Status = FileHandleDelete(FileHandle);
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_INFO, "Delete file failed: %s. Status = %r\n", FileInfo->FileName, Status));
          FileHandleClose(FileHandle);
        }
        FileHandle = NULL;  // At this point the file is always closed.  The file may also be deleted.

        DEBUG((EFI_D_INFO, "Read binary file completed. Continue to update Firmware.\n"));
        *CapsuleBuffer = FileBuffer;
        *CapsuleSize = FileSize;

        Status = VerifyCapsuleFv(FileBuffer, FileSize); // Strips header flags not needed when capsule is generated correctly
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_INFO, "VerifyCapsuleFv failed.\n"));
        } else { // Found a file and it passed verification checks
          DEBUG((EFI_D_INFO, "Passed VerifyCapsuleFv.\n"));
          FoundFile = TRUE;
          break;
        }
      }
    }
  }
  DEBUG((EFI_D_INFO, "Search partition end.\n"));

  //
  // Cleanup
  //
  if (FileHandle != NULL){
    DEBUG((EFI_D_ERROR, "Cleanup file handle.\n"));
    FileHandleClose(FileHandle);
    FileHandle = NULL;
  }
  if (FileBuffer == NULL || FileSize == 0){
    DEBUG((EFI_D_ERROR, "Cleanup file buffer.\n"));
    if (FileBuffer != NULL) {
      FreePool(FileBuffer); // Keep consistent (pool vs pages)
      FileBuffer = NULL;
    }
    return EFI_ABORTED;
  }

  DEBUG((EFI_D_ERROR, "File cleanup done.\n"));
  return Status;
}

/*
  Verify the current pointer points to a valid Capsule FV file.

  @param[in] FileBuffer          Pointer to Capsule file.
  @param[in] FileSize            Capsule file size.

  @retvalEFI_SUCCESS             The Capsule header is valid.
  @retvalEFI_VOLUME_CORRUPTED    The Capsule header is not valid.
  @retvalEFI_INVALID_PARAMETER   A required parameter was NULL.
  @retvalEFI_ABORTED             Operation aborted.
*/
EFI_STATUS
VerifyCapsuleFv (
  IN VOID                      *FileBuffer,
  IN UINTN                      FileSize
  )
{
  EFI_CAPSULE_HEADER           *CapsuleHeader = NULL;
  DEBUG((EFI_D_ERROR, "Enter VerifyCapsuleFv\n"));

  if (FileBuffer == NULL) {
    DEBUG((EFI_D_ERROR, "FileBuffer is null\n"));
    return EFI_INVALID_PARAMETER;
    }

  DEBUG((EFI_D_ERROR, "FileBuffer ok\n"));
  CapsuleHeader = (EFI_CAPSULE_HEADER *)(UINT8 *)((UINTN)FileBuffer);

  if (CapsuleHeader->CapsuleImageSize != FileSize){
    DEBUG((EFI_D_ERROR, "Invalid Capsule file, improper size detected.\n"));
    return EFI_VOLUME_CORRUPTED;
  }

  DEBUG((EFI_D_ERROR, "CapsuleHeader->Flags %x \n",CapsuleHeader->Flags));
  if ( CapsuleHeader->Flags == (CAPSULE_FLAGS_INITIATE_RESET | CAPSULE_FLAGS_PERSIST_ACROSS_RESET)){
    DEBUG((EFI_D_ERROR, "Header workaround\n"));
    CapsuleHeader->Flags = CapsuleHeader->Flags ^ (CAPSULE_FLAGS_INITIATE_RESET | CAPSULE_FLAGS_PERSIST_ACROSS_RESET);
  }
  DEBUG((EFI_D_ERROR, "Header checks ok\n"));

  return EFI_SUCCESS;
}

/**
  For a bootable Device path, return its boot type.

  @param  DevicePath                      The bootable device Path to check

  @retval BDS_EFI_MEDIA_HD_BOOT           If given device path contains MEDIA_DEVICE_PATH type device path node
                      which subtype is MEDIA_HARDDRIVE_DP
  @retval BDS_EFI_MEDIA_CDROM_BOOT        If given device path contains MEDIA_DEVICE_PATH type device path node
                      which subtype is MEDIA_CDROM_DP
  @retval BDS_EFI_ACPI_FLOPPY_BOOT        If given device path contains ACPI_DEVICE_PATH type device path node
                      which HID is floppy device.
  @retval BDS_EFI_MESSAGE_ATAPI_BOOT      If given device path contains MESSAGING_DEVICE_PATH type device path node
                      and its last device path node's subtype is MSG_ATAPI_DP.
  @retval BDS_EFI_MESSAGE_SCSI_BOOT       If given device path contains MESSAGING_DEVICE_PATH type device path node
                      and its last device path node's subtype is MSG_SCSI_DP.
  @retval BDS_EFI_MESSAGE_USB_DEVICE_BOOT If given device path contains MESSAGING_DEVICE_PATH type device path node
                      and its last device path node's subtype is MSG_USB_DP.
  @retval BDS_EFI_MESSAGE_MISC_BOOT       If the device path not contains any media device path node,  and
                      its last device path node point to a message device path node.
  @retval BDS_LEGACY_BBS_BOOT             If given device path contains BBS_DEVICE_PATH type device path node.
  @retval BDS_EFI_UNSUPPORT               An EFI Removable BlockIO device path not point to a media and message device,

**/
EFI_STATUS
CoDVerifyDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL     *DevicePath
  )
{
  ACPI_HID_DEVICE_PATH          *Acpi;
  EFI_DEVICE_PATH_PROTOCOL      *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL      *LastDeviceNode;
  EFI_STATUS                    Status;
  DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step 1\n"));
  if (NULL == DevicePath) {
    return EFI_DEVICE_ERROR;
  }

  TempDevicePath = DevicePath;
  Status = EFI_DEVICE_ERROR;

  while (!IsDevicePathEndType(TempDevicePath)) {
    switch (TempDevicePath->Type) {
    case BBS_DEVICE_PATH:
      DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step BBS_DEVICE_PATH\n"));
      return Status;
    case MEDIA_DEVICE_PATH:
      if (DevicePathSubType(TempDevicePath) == MEDIA_HARDDRIVE_DP) {
        DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step MEDIA_HARDDRIVE_DP\n"));
        Status = EFI_SUCCESS;
        return Status;
      }
      else if (DevicePathSubType (TempDevicePath) == MEDIA_CDROM_DP) {
        DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step MEDIA_CDROM_DP\n"));
        return Status;
      }
      break;
    case ACPI_DEVICE_PATH:
      Acpi = (ACPI_HID_DEVICE_PATH *) TempDevicePath;
      if (EISA_ID_TO_NUM (Acpi->HID) == 0x0604) {
         DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step 0x0604\n"));
        return Status;
      }
      break;
    case MESSAGING_DEVICE_PATH:
      //
      // Get the last device path node
      //
      LastDeviceNode = NextDevicePathNode(TempDevicePath);
      //LastDeviceNode = TempDevicePath + TempDevicePath->Length[0];
      if (DevicePathSubType(LastDeviceNode) == MSG_DEVICE_LOGICAL_UNIT_DP) {
        //
        // if the next node type is Device Logical Unit, which specify the Logical Unit Number (LUN),
        // skip it
        //
        LastDeviceNode = NextDevicePathNode(LastDeviceNode);
      }

      //
      // Check if it is the message device from sd card or emmc, we deal with it differently
      //
      if (DevicePathSubType (TempDevicePath) == MSG_EMMC_DP || DevicePathSubType (TempDevicePath) == MSG_SD_DP) {
        Status = EFI_SUCCESS;
        break;
      }
      
      //
      // if the device path not only point to driver device, it is not a messaging device path,
      //
      if (!IsDevicePathEndType(LastDeviceNode)) {
        break;
      }

      switch (DevicePathSubType(TempDevicePath)) {
      case MSG_ATAPI_DP:
      case MSG_USB_DP:
      case MSG_SCSI_DP:
      case MSG_SATA_DP:
        Status = EFI_SUCCESS;
        break;

      case MSG_MAC_ADDR_DP:
      case MSG_VLAN_DP:
      case MSG_IPv4_DP:
      case MSG_IPv6_DP:
        break;

      default:
        Status = EFI_SUCCESS;
        break;
      }
      DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step BootType\n"));
      return Status;

    default:
      break;
    }
    TempDevicePath = NextDevicePathNode(TempDevicePath);
  }
  DEBUG((EFI_D_ERROR, "GetBootTypeFromDevicePath step TempDevicePath exit\n"));
  return Status;
}

/*
Get Boot Variable Info
*/
EFI_STATUS
EFIAPI
CoDGetUpdateDevicePath(
  OUT EFI_DEVICE_PATH_PROTOCOL	**DevicePath
  )
{
  UINTN           BufferSize;
  VOID            *Buffer;
  UINTN           OrderSize;
  UINT16          *BootOrderBuffer;
  EFI_STATUS      Status;
  UINT8           *TmpPtr;
  CHAR16          BootName[20];
  UINTN           Index;

  DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath Entry\n"));

  //Attempt to get BootNext Variable Info
  BootOrderBuffer = NULL;
  OrderSize = 0;
  Status = gRT->GetVariable(L"BootNext", &gEfiGlobalVariableGuid, NULL, &OrderSize, BootOrderBuffer);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    //
    // Allocate the buffer to return
    //
    BootOrderBuffer = AllocateZeroPool(OrderSize);
    if (BootOrderBuffer == NULL) {
      OrderSize = 0;
      return EFI_OUT_OF_RESOURCES;
    } else {
      //
      // Read variable into the allocated buffer.
      //
      DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath Get BootNext Variable\n"));
      Status = gRT->GetVariable(L"BootNext", &gEfiGlobalVariableGuid, NULL, &OrderSize, BootOrderBuffer);
      if (EFI_ERROR(Status)) {
        FreePool(BootOrderBuffer);
        OrderSize = 0;
        BootOrderBuffer = NULL;
      }
    }
  }

  // If Failed to get BootNext Variable Attempt to find First Device in BootOrder
  if (BootOrderBuffer == NULL || EFI_ERROR(Status) ){
    DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath check default boot order\n"));
    BootOrderBuffer = NULL;
    OrderSize = 0;
    Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid, NULL, &OrderSize, BootOrderBuffer);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      //
      // Allocate the buffer to return
      //
      BootOrderBuffer = AllocateZeroPool(OrderSize);
      if (BootOrderBuffer == NULL) {
        OrderSize = 0;
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Read variable into the allocated buffer.
      //
      DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath read BootOrder variable\n"));
      Status = gRT->GetVariable(L"BootOrder", &gEfiGlobalVariableGuid, NULL, &OrderSize, BootOrderBuffer);
      if (EFI_ERROR(Status)) {
        FreePool(BootOrderBuffer);
        OrderSize = 0;
        BootOrderBuffer = NULL;
      }
    }
  }

  // Check to make sure boot order can be found
  if (BootOrderBuffer == NULL || OrderSize == 0) {
    DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath unable to determine boot order\n"));
    return EFI_NOT_FOUND;
  }

  // Get Default Boot Option
  Buffer = NULL;
  BufferSize = 0;
  for (Index = 0; Index < OrderSize/sizeof(UINT16); Index++){
    TmpPtr = (UINT8 *)BootOrderBuffer+(Index * sizeof(UINT16));
    UnicodeSPrint(BootName, sizeof(BootName), L"Boot%04x", *TmpPtr);
    DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath BootName: %s\n", BootName));

    // Reset variable buffer for reading next variable.
    if (Buffer != NULL) {
      FreePool(Buffer);
      BufferSize = 0;
      Buffer = NULL;
    }

    DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath get variable %s\n", BootName));
    Status = gRT->GetVariable(BootName, &gEfiGlobalVariableGuid, NULL, &BufferSize, Buffer);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      //
      // Allocate the buffer to return
      //
      Buffer = AllocateZeroPool(BufferSize);
      if (Buffer == NULL) {
        BufferSize = 0;
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Read variable into the allocated buffer.
      //
      Status = gRT->GetVariable(BootName, &gEfiGlobalVariableGuid, NULL, &BufferSize, Buffer);
      if (EFI_ERROR(Status)) {
        FreePool(Buffer);
        BufferSize = 0;
        Buffer = NULL;
        DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath failed to get variable...\n"));
      }
    } else {
      DEBUG((EFI_D_ERROR, "Unable to find %s Variable\n", BootName));
      continue;
    }

    //
    // Verify Device Path is Valid for update
    //
    TmpPtr = Buffer; //Attribute
    TmpPtr += sizeof(UINT32); //device path size
    TmpPtr += sizeof(UINT16); //description string
    DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath Device Description: %s\n", TmpPtr));
    TmpPtr += StrSize((CHAR16 *)TmpPtr); //description string size
    *DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TmpPtr;
    Status = CoDVerifyDevicePath(*DevicePath);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "CoDGetUpdateDevicePath Failed To Veiryf Device Path\n"));
      *DevicePath = NULL;
    } else {
      break;
    }
  }
  return Status;
}
