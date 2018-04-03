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

/**
Get a valid SimpleFileSystem handle from Boot device

@param[out] BootNext       The value of BootNext Variable
@param[out] Handle         The file system handle

@retval EFI_SUCCESS    Get handle successfully
@retval EFI_NOT_FOUND  No valid handle found
@retval others         Get handle failed
**/
EFI_STATUS
EFIAPI
GetUpdateHandle(
  OUT UINT16                       *BootNext,
  OUT EFI_HANDLE                   **Handle
)
{
  UINTN                           BufferSize;
  VOID                            *Buffer;
  UINTN                           OrderSize;
  VOID                            *BootOrderBuffer;
  EFI_STATUS                      Status;
  UINT8                           *TmpPtr;
  CHAR16                          BootName[20];
  UINTN                           Index;
  EFI_DEVICE_PATH_PROTOCOL        *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL        *TmpDevicePath;
  CHAR16                          *DevPathString;
  UINTN                           Size;
  UINTN                           TempSize;
  EFI_HANDLE                      *SimpleFileSystemHandles;
  UINTN                           NumberSimpleFileSystemHandles;
  UINTN                           Index2;
  EFI_HANDLE                      TempHandle;
  UINT16                          *TempValue;

  BootOrderBuffer = NULL;
  OrderSize = 0;
  Buffer = NULL;
  BufferSize = 0;

  Status = GetVariable2 (
             L"BootNext",
             &gEfiGlobalVariableGuid,
             &TempValue,
             NULL
             );
  if (!EFI_ERROR(Status)) {
    UnicodeSPrint (BootName, sizeof (BootName), L"Boot%04x", *TempValue);
    Status = GetVariable2 (
               BootName,
               &gEfiGlobalVariableGuid,
               (VOID **) &Buffer,
               NULL
    );
    if (!EFI_ERROR(Status)) {
      //
      // Get description and device path
      //
      TmpPtr = Buffer; //Attribute
      TmpPtr += sizeof(UINT32); //device path size
      TmpPtr += sizeof(UINT16); //description string
      TmpPtr += StrSize((CHAR16 *)TmpPtr); //description string size
      DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TmpPtr;  
      Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &DevicePath, &TempHandle);
      if (!EFI_ERROR(Status)) {
        *Handle = TempHandle;
        *BootNext = *TempValue;
        return EFI_SUCCESS;
      }
    }
  }

  gBS->LocateHandleBuffer(
    ByProtocol,
    &gEfiSimpleFileSystemProtocolGuid,
    NULL,
    &NumberSimpleFileSystemHandles,
    &SimpleFileSystemHandles
  );

  Status = GetVariable2(
             L"BootOrder",
             &gEfiGlobalVariableGuid,
             &BootOrderBuffer,
             &OrderSize
             );
  if (EFI_ERROR(Status)) {
    Print(L"Unable to read boot order variable\n");
    return Status;
  }

  //
  // Get Default Boot Option
  //
  for (Index = 0; Index < OrderSize / sizeof(UINT16); Index++) {
    TmpPtr = (UINT8 *)BootOrderBuffer + (Index * sizeof(UINT16));
    UnicodeSPrint(BootName, sizeof(BootName), L"Boot%04x", *TmpPtr);

    //
    // Get Boot Option Variable
    //
    if (Buffer != NULL) {
      FreePool(Buffer);
    }
    BufferSize = 0;
    Buffer = NULL;

    Status = GetVariable2(
              BootName,
              &gEfiGlobalVariableGuid,
              &Buffer,
              &BufferSize
              );
    if (EFI_ERROR(Status)) {
      BufferSize = 0;
      Buffer = NULL;
      Print(L"Unable to find %s Variable\n", BootName);
      continue;
    }

    //
    // Verify Device Path is Valid for update
    //
    TmpPtr = Buffer; //Attribute
    TmpPtr += sizeof(UINT32); //device path size
    TmpPtr += sizeof(UINT16); //description string
    TmpPtr += StrSize((CHAR16 *)TmpPtr); //description string size
    DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TmpPtr;
    DevPathString = ConvertDevicePathToText(DevicePath, TRUE, FALSE); //remove

    //
    // Have a Device Path, now attempt to locate SFS
    // 
    Size = GetDevicePathSize(DevicePath) - sizeof(EFI_DEVICE_PATH_PROTOCOL); // minus the end node

    for (Index2 = 0; Index2 < NumberSimpleFileSystemHandles; Index2++) {
      //
      // Get the device path size of SimpleFileSystem handle
      //
      TmpDevicePath = DevicePathFromHandle(SimpleFileSystemHandles[Index2]);
      DevPathString = ConvertDevicePathToText(TmpDevicePath, TRUE, FALSE); //remove
      TempSize = GetDevicePathSize(TmpDevicePath) - sizeof(EFI_DEVICE_PATH_PROTOCOL); // minus the end node

      //
      // Check whether the device path of boot option is part of the  SimpleFileSystem handle's device path
      //
      if (Size <= TempSize && CompareMem(TmpDevicePath, DevicePath, Size) == 0) {
        *BootNext = *((UINT16 *)BootOrderBuffer + Index);
        *Handle = SimpleFileSystemHandles[Index2];
        break;
      } else {
        TmpDevicePath = NULL;
      }

    }
    if (*Handle != NULL) {
      Status = EFI_SUCCESS;
      break;
    } else {
      Status = EFI_NOT_FOUND;
    }
  }

  return Status;
}

/**
Write files to a given SimpleFileSystem handle.

@param[in] Buffer          The file buffer array
@param[in] BufferSize      The file buffer size array
@param[in] BufferNum       The file buffer number
@param[in] Handle          The SimpleFileSystem handle to be written

@retval EFI_SUCCESS    Write file successfully
@retval EFI_NOT_FOUND  SFS protocol not found
@retval others         Write file failed
**/
EFI_STATUS
WriteUpdateFile(
  IN  VOID                                 **Buffer,
  IN  UINTN                                *BufferSize,
  IN  UINTN                                BufferNum,
  IN  EFI_HANDLE                           *Handle
)
{
  EFI_STATUS                          Status;
  CHAR16                              FileName[50];
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *Fs;
  EFI_FILE                            *Root;
  CHAR16                              *mDirName = L"\\efi\\UpdateCapsule";
  CHAR16                              *mDirName1 = L"\\efi";
  EFI_FILE_PROTOCOL                   *DirHandle = NULL;
  EFI_FILE                            *FileHandle = NULL;
  UINT64                              FileInfo;
  UINTN                               Index = 0;
  UINTN                               Index2 = 0;
  VOID                                *Filebuffer;
  UINTN                               FileSize;

  //
  // Get the SFS protocol from the handle
  //
  Status = gBS->HandleProtocol(Handle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR(Status)) {
    return EFI_NOT_FOUND;
  }

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

  while (BufferNum > 0) {
    UnicodeSPrint (
      FileName,
      sizeof (FileName),
      L"CoDUpdate%d.cap",
      Index ++
      );

    FileHandle = NULL;
    Status = DirHandle->Open(DirHandle, &FileHandle, FileName, EFI_FILE_MODE_READ, 0);
    FileHandleClose(FileHandle);
    if (!EFI_ERROR(Status)) {
      continue;
    }

    //
    // Open UpdateCapsule file
    //
    Status = DirHandle->Open(DirHandle, &FileHandle, FileName, EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to create %s file", FileName);
      return EFI_NOT_FOUND;
    }

    //
    // Empty the file contents #NEED TO REWRITE SECTION
    //
    Status = FileHandleGetSize(FileHandle, &FileInfo);
    if (EFI_ERROR(Status)) {
      FileHandleClose(FileHandle);
      Print(L"Error Reading %s",FileName);
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
        Print(L"Error Deleting %s", FileName);
        FileHandleClose(FileHandle);
        return Status;
      }
    }

    //
    // Write Filebuffer to file
    //
    Filebuffer = Buffer[Index2];
    FileSize = BufferSize[Index2];
    Status = FileHandleWrite(FileHandle, &FileSize, Filebuffer);
    if (EFI_ERROR(Status)) {
      Print(L"Unable to write Capsule Update to %s, Status = %r\n", FileName, Status);
      return EFI_NOT_FOUND;
    }

    FileHandleClose(FileHandle);
    Index2 ++;
    BufferNum --;
  }

  return Status;
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
  @param[in]  CapsuleNum       The count of capsule images

  @retval EFI_SUCCESS       Capsule on disk secceed.
**/
EFI_STATUS
ProcessCapsuleOnDisk (
  IN VOID                          **CapsuleBuffer,
  IN UINTN                         *FileSize,
  IN UINTN                         CapsuleNum
  )
{
  EFI_STATUS                    Status;
  UINT16                        BootNext;
  EFI_HANDLE                    *Handle;

  //
  // Get a valid file system from boot path
  //
  Handle = NULL;

  Status = GetUpdateHandle(&BootNext, &Handle);
  if (EFI_ERROR(Status)) {
    Print(L"CapsuleApp: cannot find a valid file system on boot devies. Status = %r\n", Status);
    return Status;
  }

  //
  // Copy capsule image to '\efi\UpdateCapsule\'
  //
  Status = WriteUpdateFile (CapsuleBuffer, FileSize, CapsuleNum, Handle);
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

  return EFI_SUCCESS;

}