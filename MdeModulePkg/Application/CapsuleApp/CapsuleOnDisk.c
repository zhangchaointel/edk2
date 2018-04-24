/** @file
  Process Capsule On Disk.

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Guid/GlobalVariable.h>
#include <Library/DevicePathLib.h>
#include <Library/FileHandleLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Guid/Gpt.h>


BOOLEAN
CheckCapsuleOnDiskFlag(
  VOID
  )
{
  EFI_STATUS            Status;
  UINT64                OsIndication;
  UINTN                 DataSize;

  //
  // Reset OsIndication File Capsule Delivery Supported Flag
  //
  OsIndication = 0;
  DataSize     = sizeof(UINT64);
  Status = gRT->GetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &DataSize,
                  &OsIndication
                  );
  if (!EFI_ERROR(Status) && 
      (OsIndication & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) != 0) {
    return TRUE;
  }

  return FALSE;
}

/*
  Check if Active Efi System Partition within GPT is in the device path

*/
EFI_STATUS
GetEfiSysPartitionFromDevPath(
  IN EFI_DEVICE_PATH_PROTOCOL         *DevicePath,
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **Fs
  )
{
  EFI_STATUS                 Status;
  EFI_DEVICE_PATH_PROTOCOL	 *TempDevicePath;
  HARDDRIVE_DEVICE_PATH      *Hd;
  EFI_HANDLE                 Handle;

  //
  // Check if the device path contains GPT node 
  //
  TempDevicePath = DevicePath;
  while (!IsDevicePathEnd (TempDevicePath)) {
    if ((DevicePathType (TempDevicePath) == MEDIA_DEVICE_PATH) &&
       (DevicePathSubType (TempDevicePath) == MEDIA_HARDDRIVE_DP)) {
      Hd = (HARDDRIVE_DEVICE_PATH *)TempDevicePath;
      if (Hd->MBRType == MBR_TYPE_EFI_PARTITION_TABLE_HEADER) {
        break;
      }
    }
    TempDevicePath = NextDevicePathNode (TempDevicePath);
  }

  if (!IsDevicePathEnd (TempDevicePath)) {
    //
    // Search for EFI system partition protocol on full device path in Boot Option 
    //
    Status = gBS->LocateDevicePath (&gEfiPartTypeSystemPartGuid, &DevicePath, &Handle);

    //
    // Search for simple file system on this handler
    //
    if (!EFI_ERROR (Status)) {
      Status = gBS->HandleProtocol (Handle, &gEfiSimpleFileSystemProtocolGuid, Fs);
      if (!EFI_ERROR (Status)) {
        return EFI_SUCCESS;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
Get SimpleFileSystem handle from device path

@param[in]  DevicePath     The device path
@param[out] Handle         The file system handle

@retval EFI_SUCCESS    Get handle successfully
@retval EFI_NOT_FOUND  No valid handle found
@retval others         Get handle failed
**/
EFI_STATUS
EFIAPI
GetSimpleFileSystemHandleFromDevPath (
  IN  EFI_DEVICE_PATH_PROTOCOL         *DevicePath,
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  **Fs
  ) 
{
  EFI_STATUS                        Status;
  EFI_DEVICE_PATH_PROTOCOL          *CurFullPath;
  EFI_DEVICE_PATH_PROTOCOL          *PreFullPath;


  CurFullPath = NULL;
  //
  // Try every full device Path generated from bootoption 
  //
  do {
    PreFullPath = CurFullPath;
    CurFullPath = EfiBootManagerGetNextFullDevicePath (DevicePath, CurFullPath);

    if (PreFullPath != NULL) {
      FreePool (PreFullPath);
    }

    if (CurFullPath == NULL) {
      //
      // No Active EFI system partition is found in BootOption device path
      //
      Status = EFI_NOT_FOUND;
      break;
    }

    DEBUG_CODE (
      CHAR16 *DevicePathStr;
 
      DevicePathStr = ConvertDevicePathToText (CurFullPath, TRUE, TRUE);
      if (DevicePathStr != NULL){
        DEBUG ((DEBUG_INFO, "Full device path %s\n", DevicePathStr));
        FreePool (DevicePathStr);
      } 
    );
  
    Status = GetEfiSysPartitionFromDevPath (CurFullPath, Fs);
  } while (EFI_ERROR (Status));
 
  if (*Fs != NULL) {
    return EFI_SUCCESS;
  } else {
    return EFI_NOT_FOUND;
  }
}

/**
Get a valid SimpleFileSystem handle from Boot device

@param[out] BootNext        The value of BootNext Variable
@param[out] Handle          The file system handle
@param[out] UpdateBootNext  The flag to indicate whether update BootNext Variable

@retval EFI_SUCCESS    Get handle successfully
@retval EFI_NOT_FOUND  No valid handle found
@retval others         Get handle failed
**/
EFI_STATUS
EFIAPI
GetUpdateHandle(
  OUT UINT16                           *BootNext,
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  **Fs,
  OUT BOOLEAN                          *UpdateBootNext
)
{
  EFI_STATUS                      Status;
  CHAR16                          BootOptionName[20];
  UINTN                           Index;
  EFI_DEVICE_PATH_PROTOCOL        *DevicePath;
  UINT16                          *TempValue;
  EFI_BOOT_MANAGER_LOAD_OPTION    BootNextOptionEntry;
  EFI_BOOT_MANAGER_LOAD_OPTION    *BootOptionBuffer;
  UINTN                           BootOptionCount;

  if (CheckCapsuleOnDiskFlag ()) {
    Status = GetVariable2 (
               L"BootNext",
               &gEfiGlobalVariableGuid,
               &TempValue,
               NULL
               );
    if (!EFI_ERROR(Status)) {
      UnicodeSPrint (BootOptionName, sizeof (BootOptionName), L"Boot%04x", *TempValue);
      Status = EfiBootManagerVariableToLoadOption (BootOptionName, &BootNextOptionEntry);
      if (!EFI_ERROR(Status)) {
        Status = GetSimpleFileSystemHandleFromDevPath (BootNextOptionEntry.FilePath, Fs);
        if (!EFI_ERROR(Status)) {
          *UpdateBootNext = FALSE;
          return EFI_SUCCESS;
        }
      }
    }
  }

  BootOptionBuffer = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);
  if (BootOptionCount == 0) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < BootOptionCount; Index ++) {
    //
    // Get the boot option from the link list
    //
    DevicePath  = BootOptionBuffer[Index].FilePath;

    //
    // Skip inactive or legacy boot options
    //
    if ((BootOptionBuffer[Index].Attributes & LOAD_OPTION_ACTIVE) == 0 ||
        DevicePathType (DevicePath) == BBS_DEVICE_PATH) {
      continue;
    }

    DEBUG_CODE (
      CHAR16 *DevicePathStr;

      DevicePathStr = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
      if (DevicePathStr != NULL){
        DEBUG((DEBUG_INFO, "Try BootOption %s\n", DevicePathStr));
        FreePool(DevicePathStr);
      } else {
        DEBUG((DEBUG_INFO, "DevicePathToStr failed\n"));
      }
    );

    Status = GetSimpleFileSystemHandleFromDevPath (DevicePath, Fs);
    if (!EFI_ERROR(Status)) {
      *BootNext = (UINT16) BootOptionBuffer[Index].OptionNumber;
      *UpdateBootNext = TRUE;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
Write files to a given SimpleFileSystem handle.

@param[in] Buffer          The file buffer array
@param[in] BufferSize      The file buffer size array
@param[in] FileName        The file file name array
@param[in] BufferNum       The file buffer number
@param[in] Fs              The SimpleFileSystem handle to be written

@retval EFI_SUCCESS    Write file successfully
@retval EFI_NOT_FOUND  SFS protocol not found
@retval others         Write file failed
**/
EFI_STATUS
WriteUpdateFile(
  IN  VOID                                 **Buffer,
  IN  UINTN                                *BufferSize,
  IN  CHAR16                               **FileName,
  IN  UINTN                                BufferNum,
  IN  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL      *Fs
)
{
  EFI_STATUS                          Status;
  EFI_FILE                            *Root;
  CHAR16                              *mDirName = L"\\efi\\UpdateCapsule";
  CHAR16                              *mDirName1 = L"\\efi";
  EFI_FILE_PROTOCOL                   *DirHandle = NULL;
  EFI_FILE                            *FileHandle = NULL;
  UINT64                              FileInfo;
  UINTN                               Index = 0;
  VOID                                *Filebuffer;
  UINTN                               FileSize;

  //
  // Open Root from SFS
  //
  Status = Fs->OpenVolume(Fs, &Root);
  if (EFI_ERROR(Status)) {
    Print(L"Cannot open volume. Status = %r\n", Status);
    return EFI_NOT_FOUND;
  }

  //
  // Ensure that efi and updatecapsule directories exist
  //
  Status = Root->Open(Root, &DirHandle, mDirName1, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE , 0);
  if (EFI_ERROR(Status)) {
    Status = Root->Open(Root, &DirHandle, mDirName1, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, EFI_FILE_DIRECTORY);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to create %s directory", mDirName1);
      return EFI_NOT_FOUND;
    }
  }
  Status = Root->Open(Root, &DirHandle, mDirName, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE , 0);
  if (EFI_ERROR(Status)) {
    Status = Root->Open(Root, &DirHandle, mDirName, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, EFI_FILE_DIRECTORY);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to create %s directory", mDirName);
      return EFI_NOT_FOUND;
    }
  }

  for (Index = 0; Index < BufferNum; Index ++) {
    FileHandle = NULL;

    //
    // Open UpdateCapsule file
    //
    Status = DirHandle->Open(DirHandle, &FileHandle, FileName[Index], EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to create %s file", FileName[Index]);
      return EFI_NOT_FOUND;
    }

    //
    // Empty the file contents #NEED TO REWRITE SECTION
    //
    Status = FileHandleGetSize(FileHandle, &FileInfo);
    if (EFI_ERROR(Status)) {
      FileHandleClose(FileHandle);
      Print(L"Error Reading %s", FileName[Index]);
      return EFI_DEVICE_ERROR;
    }

    //
    // If the file size is already 0, then it has been empty.
    //
    if (FileInfo != 0) {
      //
      // Set the file size to 0.
      //
      FileInfo = 0;
      Status = FileHandleSetSize(FileHandle, FileInfo);
      if (EFI_ERROR(Status)) {
        Print(L"Error Deleting %s", FileName[Index]);
        FileHandleClose(FileHandle);
        return Status;
      }
    }

    //
    // Write Filebuffer to file
    //
    Filebuffer = Buffer[Index];
    FileSize = BufferSize[Index];
    Status = FileHandleWrite(FileHandle, &FileSize, Filebuffer);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to write Capsule Update to %s, Status = %r\n", FileName[Index], Status);
      return EFI_NOT_FOUND;
    }

    FileHandleClose(FileHandle);
  }

  return EFI_SUCCESS;
}

/**
  Set capsule status variable.

  @retval EFI_SUCCESS            The capsule status variable is cleared.
**/
EFI_STATUS
SetCapsuleStatusVariable(
  BOOLEAN                       SetCap
  )
{
  EFI_STATUS                    Status;
  UINT64                        OsIndication;
  UINTN                         DataSize;
  
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
  if (SetCap) {
    OsIndication |= ((UINT64)EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED);
  }
  else {
    OsIndication &= ~((UINT64)EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED);
  }
  Status = gRT->SetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  sizeof(UINT64),
                  &OsIndication
                  );

  return Status;
}

/**
  Process Capsule On Disk.

  @param[in]  CapsuleBuffer    An array of pointer to capsule images
  @param[in]  FileSize         An array of UINTN to capsule images size
  @param[in]  FileName         An array of UINTN to capsule images name
  @param[in]  CapsuleNum       The count of capsule images

  @retval EFI_SUCCESS       Capsule on disk secceed.
**/
EFI_STATUS
ProcessCapsuleOnDisk (
  IN VOID                          **CapsuleBuffer,
  IN UINTN                         *FileSize,
  IN CHAR16                        **FileName,
  IN UINTN                         CapsuleNum
  )
{
  EFI_STATUS                      Status;
  UINT16                          BootNext;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  BOOLEAN                         UpdateBootNext;

  //
  // Get a valid file system from boot path
  //
  Fs = NULL;

  Status = GetUpdateHandle(&BootNext, &Fs, &UpdateBootNext);
  if (EFI_ERROR(Status)) {
    Print(L"CapsuleApp: cannot find a valid file system on boot devies. Status = %r\n", Status);
    return Status;
  }

  //
  // Copy capsule image to '\efi\UpdateCapsule\'
  //
  Status = WriteUpdateFile (CapsuleBuffer, FileSize, FileName, CapsuleNum, Fs);
  if (EFI_ERROR (Status)) {
    Print(L"CapsuleApp: capsule image could not be copied for update.\n");
    return Status;
  }

  //
  // Set variable then reset
  //
  Status = SetCapsuleStatusVariable (TRUE);
  if (EFI_ERROR (Status)) {
    Print(L"CapsuleApp: unable to set OSIndication variable.\n");
    return Status;
  }

  if (UpdateBootNext) {
    Status = gRT->SetVariable (
      L"BootNext",
      &gEfiGlobalVariableGuid,
      EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
      sizeof(UINT16),
      &BootNext
      );
    if (EFI_ERROR(Status)){
      Print(L"CapsuleApp: unable to set BootNext variable.\n");
      return Status;
    }
  }

  return EFI_SUCCESS;
}