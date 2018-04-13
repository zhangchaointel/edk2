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
#include <Uefi.h>
#include <Pi/PiMultiPhase.h>

#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/FileHandleLib.h>
#include <Library/CapsuleLib.h>
#include <Library/DevicePathLib.h>
#include <Library/GenericBdsLib.h>
#include <Library/PrintLib.h>
#include <Library/CodLib.h>

#include <Protocol/SimpleFileSystem.h>
#include <Protocol/UsbIo.h>
#include <Guid/GlobalVariable.h>

#include "InternalCoDLib.h"

EFI_STATUS
CheckCoDDirectory(
  EFI_DEVICE_PATH *DevPath
  )
{
  EFI_STATUS                      Status;
  EFI_HANDLE                      DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL        *HandleFilePath;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_FILE_HANDLE                  RootDir;
  EFI_FILE_HANDLE                  FileDir;

  //
  // Try to get the image device handle by checking the match protocol.
  //
  HandleFilePath = DevPath;
  RootDir        = NULL;
  FileDir        = NULL;

  Status =  gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &HandleFilePath, &DeviceHandle);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  Status = gBS->HandleProtocol(DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, &Fs);
  Status = Fs->OpenVolume(Fs, &RootDir);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = RootDir->Open(
                      RootDir,
                      &FileDir,
                      EFI_CAPSULE_FROM_FILE_DIR,
                      EFI_FILE_MODE_READ,
                      0
                      );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (FileDir != NULL) {
    FileDir->Close (FileDir);
  }

  if (RootDir != NULL) {
    RootDir->Close (RootDir);
  }

  return EFI_SUCCESS;

}


/**
  Find a USB device path which match the specified short-form device path start
  with USB Class or USB WWID device path and load the boot file then return the 
  image handle. If ParentDevicePath is NULL, this function will search in all USB
  devices of the platform. If ParentDevicePath is not NULL,this function will only
  search in its child devices.
  Caller is reposible to free the memroy pointed by FullDevicePath

  @param ParentDevicePath      The device path of the parent.
  @param ShortFormDevicePath   The USB Class or USB WWID device path to match.

  @return  The image Handle if find load file from specified short-form device path
           or NULL if not found.

**/
EFI_STATUS
FindCoDUsbDevice (
  IN  EFI_DEVICE_PATH_PROTOCOL   *ParentDevicePath,
  IN  EFI_DEVICE_PATH_PROTOCOL   *ShortFormDevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL   **FullDevicePath
  )
{
  EFI_STATUS                Status;
  UINTN                     UsbIoHandleCount;
  EFI_HANDLE                *UsbIoHandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL  *UsbIoDevicePath;
  EFI_USB_IO_PROTOCOL       *UsbIo;
  UINTN                     Index;
  UINTN                     ParentSize;
  UINTN                     Size;
  EFI_HANDLE                ImageHandle;
  EFI_HANDLE                Handle;
  EFI_DEVICE_PATH_PROTOCOL  *FullDevicePathTemp;
  EFI_DEVICE_PATH_PROTOCOL  *NextDevicePath;

  FullDevicePathTemp = NULL;
  ImageHandle        = NULL;

  //
  // Get all UsbIo Handles.
  //
  UsbIoHandleCount = 0;
  UsbIoHandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiUsbIoProtocolGuid,
                  NULL,
                  &UsbIoHandleCount,
                  &UsbIoHandleBuffer
                  );
  if (EFI_ERROR (Status) || (UsbIoHandleCount == 0) || (UsbIoHandleBuffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ParentSize = (ParentDevicePath == NULL) ? 0 : GetDevicePathSize (ParentDevicePath);
  for (Index = 0; Index < UsbIoHandleCount; Index++) {
    //
    // Get the Usb IO interface.
    //
    Status = gBS->HandleProtocol(
                    UsbIoHandleBuffer[Index],
                    &gEfiUsbIoProtocolGuid,
                    (VOID **) &UsbIo
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    UsbIoDevicePath = DevicePathFromHandle (UsbIoHandleBuffer[Index]);
    if (UsbIoDevicePath == NULL) {
      continue;
    }

    if (ParentDevicePath != NULL) {
      //
      // Compare starting part of UsbIoHandle's device path with ParentDevicePath.
      //
      Size = GetDevicePathSize (UsbIoDevicePath);
      if ((Size < ParentSize) ||
          (CompareMem (UsbIoDevicePath, ParentDevicePath, ParentSize - END_DEVICE_PATH_LENGTH) != 0)) {
        continue;
      }
    }

    if (BdsMatchUsbClass (UsbIo, (USB_CLASS_DEVICE_PATH *) ShortFormDevicePath) ||
        BdsMatchUsbWwid (UsbIo, (USB_WWID_DEVICE_PATH *) ShortFormDevicePath)) {
      //
      // Try to find if there is the boot file in this DevicePath
      //
      NextDevicePath = NextDevicePathNode (ShortFormDevicePath);
      if (!IsDevicePathEnd (NextDevicePath)) {
        FullDevicePathTemp = AppendDevicePath (UsbIoDevicePath, NextDevicePath);
        //
        // Connect the full device path, so that Simple File System protocol
        // could be installed for this USB device.
        //
        BdsLibConnectDevicePath (FullDevicePathTemp);
        Status = CheckCoDDirectory(FullDevicePathTemp);
        if (EFI_ERROR(Status)) {
          FreePool(FullDevicePathTemp);
        }
      } else {
        Status = EFI_NOT_FOUND;
      }

      //
      // If we didn't find an image directly, we need to try as if it is a removable device boot option
      // and load the image according to the default boot behavior for removable device.
      //
      if (EFI_ERROR (Status)) {
        //
        // check if there is a bootable removable media could be found in this device path ,
        // and get the bootable media handle
        //
        Handle = BdsLibGetBootableHandle(UsbIoDevicePath);
        if (Handle == NULL) {
          continue;
        }
        //
        // Check the Capsule On Disk directory \EFI\UpdateCapsule\
        //
        FullDevicePathTemp = DuplicateDevicePath(UsbIoDevicePath);
        if (FullDevicePathTemp != NULL) {
          Status = CheckCoDDirectory(FullDevicePathTemp);
          
          if (EFI_ERROR (Status)) {
            //
            // The DevicePath failed, and it's not a valid
            // removable media device.
            //
            FreePool(FullDevicePathTemp);
            continue;
          }
        } else {
          continue;
        }
      }

      *FullDevicePath = FullDevicePathTemp;
      break;
    }
  }

  FreePool (UsbIoHandleBuffer);

  return Status;
}


/**
  Expand USB Class or USB WWID device path node to be full device path of a USB
  device in platform then load the boot file on this full device path and return the 
  image handle.

  This function support following 4 cases:
  1) Boot Option device path starts with a USB Class or USB WWID device path,
     and there is no Media FilePath device path in the end.
     In this case, it will follow Removable Media Boot Behavior.
  2) Boot Option device path starts with a USB Class or USB WWID device path,
     and ended with Media FilePath device path.
  3) Boot Option device path starts with a full device path to a USB Host Controller,
     contains a USB Class or USB WWID device path node, while not ended with Media
     FilePath device path. In this case, it will follow Removable Media Boot Behavior.
  4) Boot Option device path starts with a full device path to a USB Host Controller,
     contains a USB Class or USB WWID device path node, and ended with Media
     FilePath device path.

  @param  DevicePath    The Boot Option device path.

  @return  The image handle of boot file, or NULL if there is no boot file found in
           the specified USB Class or USB WWID device path.

**/
EFI_STATUS
ExpandUsbShortFormDevicePathForCod (
  IN  EFI_DEVICE_PATH_PROTOCOL       *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL       **FullDevicePath
  )
{
  EFI_STATUS                Status;
  EFI_DEVICE_PATH_PROTOCOL  *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *ShortFormDevicePath;

  //
  // Search for USB Class or USB WWID device path node.
  //
  ShortFormDevicePath = NULL;
  *FullDevicePath     = NULL;
  TempDevicePath      = DevicePath;

  while (!IsDevicePathEnd (TempDevicePath)) {
    if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
        ((DevicePathSubType (TempDevicePath) == MSG_USB_CLASS_DP) ||
         (DevicePathSubType (TempDevicePath) == MSG_USB_WWID_DP))) {
      ShortFormDevicePath = TempDevicePath;
      break;
    }
    TempDevicePath = NextDevicePathNode (TempDevicePath);
  }

  if (ShortFormDevicePath == NULL) {
    //
    // No USB Class or USB WWID device path node found, do nothing.
    //
    return EFI_INVALID_PARAMETER;
  }

  if (ShortFormDevicePath == DevicePath) {
    //
    // Boot Option device path starts with USB Class or USB WWID device path.
    //
    Status = FindCoDUsbDevice (NULL, ShortFormDevicePath, FullDevicePath);
    if (EFI_ERROR(Status)) {
      //
      // Failed to find a match in existing devices, connect the short form USB
      // device path and try again.
      //
      BdsLibConnectUsbDevByShortFormDP (0xff, ShortFormDevicePath);
      Status = FindCoDUsbDevice (NULL, ShortFormDevicePath, FullDevicePath);
    }
  } else {
    //
    // Boot Option device path contains USB Class or USB WWID device path node.
    //

    //
    // Prepare the parent device path for search.
    //
    TempDevicePath = DuplicateDevicePath (DevicePath);
    ASSERT (TempDevicePath != NULL);
    SetDevicePathEndNode (((UINT8 *) TempDevicePath) + ((UINTN) ShortFormDevicePath - (UINTN) DevicePath));

    //
    // The USB Host Controller device path is already in Boot Option device path
    // and USB Bus driver already support RemainingDevicePath starts with USB
    // Class or USB WWID device path, so just search in existing USB devices and
    // doesn't perform ConnectController here.
    //
    Status = FindCoDUsbDevice (TempDevicePath, ShortFormDevicePath, FullDevicePath);
    FreePool (TempDevicePath);
  }

  return Status;
}


/**

   This routine is called to set a new capsule status to variable
  The variable name is L"CapsuleXXXX"
  
  @param[in]   CapsuleStatus              capsule process status

  @retval upper cased string after process

**/
STATIC
CHAR16 *
UpperCaseString (
  IN CHAR16 *Str
  )
{
  CHAR16  *Cptr;

  for (Cptr = Str; *Cptr; Cptr++) {
    if (L'a' <= *Cptr && *Cptr <= L'z') {
      *Cptr = *Cptr - L'a' + L'A';
    }
  }

  return Str;
}

/**

   This routine is used to return substring before period '.' or '\0'
   Caller owns substr space allocation & free
  
  @param[in]   CapsuleStatus              capsule process status

  @retval upper cased string after process

**/
STATIC
VOID
GetSubStringBeforePeriod (
   IN  CHAR16 *Str, 
   OUT CHAR16 *SubStr, 
   OUT UINTN  *SubStrLen
  )
{
  UINTN Index;
  for (Index = 0; Str[Index] != L'.' && Str[Index] != L'\0'; Index++) {
    SubStr[Index] = Str[Index]; 
  }

  SubStr[Index] = L'\0';
  *SubStrLen = Index;

}

/**

   This routine pad the string in tail with input character.
  
  @param[in]   StrBuf              Str buffer to be padded, should be enough room for 
  @param[in]   PadLen             Expected padding length
  @param[in]   Character         Character used to pad

**/
STATIC
VOID
PadStrInTail (
   IN CHAR16   *StrBuf, 
   IN UINTN    PadLen, 
   IN CHAR16   Character
  )
{
  UINTN Index;

  for (Index = 0; StrBuf[Index] != L'\0'; Index++);

  while(PadLen != 0) {
    StrBuf[Index] = Character;
    Index++;
    PadLen--;
  }

  StrBuf[Index] = L'\0';
 }

/**

   This routine find the offset of the last period '.' of string. if No period exists
   function FileNameExtension is set to L'\0'
  
  @param[in]   FileName                File name to split between last period
  @param[out] FileNameFirst          First FileName before last period
  @param[out] FileNameExtension  FileName after last period
  
**/
STATIC
VOID
SplitFileNameExtension (
   IN CHAR16   *FileName,
   OUT CHAR16  *FileNameFirst,
   OUT CHAR16  *FileNameExtension
  )
{
  UINTN Index;
  UINTN StringLen;

  StringLen = StrLen(FileName);
  for (Index = StringLen; Index > 0 && FileName[Index] != L'.'; Index--);

  //
  // No period exists. No FileName Extension
  //
  if (Index == 0 && FileName[Index] != L'.') {
    FileNameExtension[0] = L'\0';
    Index = StringLen;
  } else {
    StrCpy(FileNameExtension, &FileName[Index+1]);
  }

  //
  // Copy First file name
  //
  StrnCpy(FileNameFirst, FileName, Index);
  FileNameFirst[Index] = L'\0';

}

/**

  This routine is called to get all boot options determnined by  
     1. "BootNext"
     2. "BootOrder"

  @param[out] BootLists           BootList points to all boot options returned

  @retval EFI_SUCCESS             There is no error when processing capsule

**/
EFI_STATUS
GetDefaultActiveBootOptionList(
  OUT LIST_ENTRY  *BootLists
  )
{
  UINTN     DataSize;
  UINT16    *BootNext;
  CHAR16    VariableName[20];

  BootNext = NULL;

  InitializeListHead (BootLists);

  //
  // Check if we have the boot next option
  //
  BootNext = BdsLibGetVariableAndSize (
               L"BootNext",
               &gEfiGlobalVariableGuid,
               &DataSize
               );
  if (BootNext != NULL && DataSize == sizeof(UINT16)) {
    //
    // Add the boot next boot option
    //
    UnicodeSPrint (VariableName, sizeof (VariableName), L"Boot%04x", *BootNext);

    BdsLibVariableToOption (BootLists, VariableName);

    if (BootNext != NULL) {
      FreePool(BootNext);
    }
  }

  //
  // Parse the boot order to get boot option
  //
  return BdsLibBuildOptionFromVar (BootLists, L"BootOrder");
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
     if (!EFI_ERROR(Status)) {
       Status = gBS->HandleProtocol(Handle, &gEfiSimpleFileSystemProtocolGuid, Fs);
       if (!EFI_ERROR(Status)) {
         return EFI_SUCCESS;
       }
     }
   }

   return EFI_NOT_FOUND;
}
/**

  This routine is called to get Simple File System protocol on the first EFI system partition found in  
  active boot option. The boot option list is detemined in order by 
     1. "BootNext"
     2. "BootOrder"

  @param[out] Fs          Simple File System Protocol found for first active EFI system partition

  @retval EFI_SUCCESS     Simple File System protocol found for EFI system partition
  @retval EFI_NOT_FOUND   No Simple File System protocol found for EFI system partition

**/
EFI_STATUS 
GetEfiSysPartitionFromActiveBootOption(
  IN  UINTN                            MaxTryCount,
  IN  LIST_ENTRY                       *ActiveBootLists, OPTIONAL
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  **Fs
  )
{
  EFI_STATUS                   Status;
  BDS_COMMON_OPTION            *BootOption;
  LIST_ENTRY                   DefaultBootLists;
  LIST_ENTRY                   *BootLists;
  LIST_ENTRY                   *Link;
  EFI_DEVICE_PATH_PROTOCOL     *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL     *TempDevicePath;
  EFI_HANDLE                   *FsHandleBuf;
  BOOLEAN                      ShortFormedDevPath;
  UINTN                        FsHandleNum;
  UINTN                        Index;

  *Fs              = NULL;
  TempDevicePath   = NULL;

  if (ActiveBootLists == NULL) {
    Status = GetDefaultActiveBootOptionList(&DefaultBootLists);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "GetDefaultActiveBootOptionList Failed %x!\n", Status));
      return Status;
    }
    BootLists = &DefaultBootLists;
  } else {
    BootLists = ActiveBootLists;
  }

  //
  // Search BootOptionList to check if it is an active boot option with EFI system partition
  //  1. Connect device path
  //  2. expend short/plug in devicepath
  //  3. LoadImage
  //
  for (Link = BootLists->ForwardLink; Link != BootLists; Link = Link->ForwardLink) {
    //
    // Get the boot option from the link list
    //
    BootOption = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);
    DevicePath = BootOption->DevicePath;

    DEBUG_CODE (
      CHAR16 *DevicePathStr;

      DevicePathStr = DevicePathToStr(DevicePath);
      if (DevicePathStr != NULL){
        DEBUG((DEBUG_INFO, "Try BootOption %s\n", DevicePathStr));
        FreePool(DevicePathStr);
      } else {
        DEBUG((DEBUG_INFO, "DevicePathToStr failed\n"));
      }
    );

    //
    // Skip LOAD_OPTION_ACTIVE boot option &  BBS device path
    //
    if (!IS_LOAD_OPTION_TYPE (BootOption->Attribute, LOAD_OPTION_ACTIVE) ||
        DevicePathType (DevicePath) == BBS_DEVICE_PATH) {
      continue;
    }

    //
    // Make sure the boot option device path connected.
    // Only handle first device in boot option. Other optional device paths are described as OSV specific
    //
    BdsLibConnectDevicePath (DevicePath);

    //
    // If it's Device Path that starts with a hard drive path, append it with the front part to compose a
    // full device path
    //
    if ((DevicePathType (DevicePath) == MEDIA_DEVICE_PATH) &&
        (DevicePathSubType (DevicePath) == MEDIA_HARDDRIVE_DP)) {
      if ((((HARDDRIVE_DEVICE_PATH *)DevicePath)->MBRType & MBR_TYPE_EFI_PARTITION_TABLE_HEADER) != 0) {
        TempDevicePath = BdsExpandPartitionPartialDevicePathToFull ((HARDDRIVE_DEVICE_PATH *)DevicePath);
        if (TempDevicePath != NULL) {
          DevicePath = TempDevicePath;
        }
      }
    }

    //
    // Expand USB Class or USB WWID device path node to be full device path of a USB
    // device in platform then load the boot file on this full device path and get the
    // image handle.
    //
    if (BdsLibCheckUsbDevicePath(DevicePath, &ShortFormedDevPath)) {
      while (MaxTryCount > 0) {
        if (ShortFormedDevPath) {
          TempDevicePath = NULL;
          Status = ExpandUsbShortFormDevicePathForCod (DevicePath, &TempDevicePath);
          if (!EFI_ERROR(Status)) {
            DevicePath = TempDevicePath;
            break;
          }
        } else {
          Status = BdsLibConnectDevicePath(DevicePath);
          if (!EFI_ERROR(Status)) {
            break;
          }
        }

        //
        // Stall 100ms if connection failed to ensure USB stack is ready.
        //
        gBS->Stall(100000);
        MaxTryCount --;
      }
    }

#if 1
    Status = GetEfiSysPartitionFromDevPath(DevicePath, Fs);
    if (EFI_ERROR(Status)) {
      //
      // The device may not longer enough to produce simple file system. Try to recursive connect
      // to check 
      //
      Status = BdsLibGetSimpleFileSystemHandlesFromDevPath (
                 DevicePath,
                 &FsHandleBuf,
                 &FsHandleNum
                 );
      if (!EFI_ERROR(Status)) {
        for (Index = 0; Index < FsHandleNum; Index++) {
          if (FsHandleBuf[Index] != NULL) {
            gBS->HandleProtocol(FsHandleBuf[Index], &gEfiDevicePathProtocolGuid, &DevicePath);
            Status = GetEfiSysPartitionFromDevPath(DevicePath, Fs);
            if (!EFI_ERROR(Status)) {
              break;
            }
          }
        }
      }
    }else {
      break;
    }

#else
    //
    // Search for EFI system partition protocol on full device path in Boot Option 
    //
    Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &DevicePath, &Handle);
    if (!EFI_ERROR(Status)) {
      Status = gBS->HandleProtocol(Handle, &gEfiSimpleFileSystemProtocolGuid, Fs);
      if (!EFI_ERROR(Status)) {
        break;
      }
    }

#endif


  }

  //
  // No qualified EFI system partition found
  //
  if (*Fs == NULL) {
    Status = EFI_NOT_FOUND;
  }

  DEBUG_CODE (
    CHAR16 *DevicePathStr1;
    if (*Fs != NULL) {
      DevicePathStr1 = DevicePathToStr(DevicePath);
      if (DevicePathStr1 != NULL){
        DEBUG((DEBUG_INFO, "Found Active EFI System Partion on %s\n", DevicePathStr1));
        FreePool(DevicePathStr1);
      } 
    } else {
      DEBUG((DEBUG_INFO, "Failed to found Active EFI System Partion\n"));
    }
  );

  //
  // Free all BootOption entry on list
  //
  while(!IsListEmpty(&DefaultBootLists)) {
    Link = DefaultBootLists.ForwardLink;
    RemoveEntryList(Link);
    //
    // Get the boot option from the link list
    //
    BootOption = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    FreePool(BootOption->DevicePath);
    FreePool(BootOption->Description);
    FreePool(BootOption->LoadOptions);
    FreePool(BootOption);
  }

  return Status;
}


/**

  This routine is called to get all file infos with in a given dir & with given file attribute, the file info is listed in
  alphabetical order described in UEFI spec. 

  @param[in]  Dir                 Directory file handler
  @param[in]  FileAttr            Attribute of file to be red from directory
  @param[out] FileInfoList        File images info list red from directory
  @param[out] FileNum             File images number red from directory

  @retval EFI_SUCCESS             file FileInfo list in the given  

**/
EFI_STATUS
GetFileInfoListInAlphabetFromDir(
  IN EFI_FILE_HANDLE  Dir,
  IN UINT64           FileAttr,
  OUT LIST_ENTRY      *FileInfoList,
  OUT UINTN           *FileNum
  )
{
  EFI_STATUS        Status;
  FILE_INFO_ENTRY   *NewFileInfoEntry;
  FILE_INFO_ENTRY   *TempFileInfoEntry;
  EFI_FILE_INFO     *FileInfo;
  CHAR16            *NewFileName;
  CHAR16            *ListedFileName;
  CHAR16            *NewFileNameExtension;
  CHAR16            *ListedFileNameExtension;
  CHAR16            *TempNewSubStr;
  CHAR16            *TempListedSubStr;
  LIST_ENTRY        *Link;
  BOOLEAN           NoFile;
  UINTN             FileCount;
  UINTN             IndexNew;
  UINTN             IndexListed;
  UINTN             NewSubStrLen;
  UINTN             ListedSubStrLen;
  INTN              SubStrCmpResult;

  Status                  = EFI_SUCCESS;
  NewFileName             = NULL;
  ListedFileName          = NULL;
  NewFileNameExtension    = NULL;
  ListedFileNameExtension = NULL;
  TempNewSubStr           = NULL;
  TempListedSubStr        = NULL;
  NoFile                  = FALSE;
  FileCount               = 0;

  InitializeListHead(FileInfoList);

  TempNewSubStr           = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);
  TempListedSubStr        = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);

  if (TempNewSubStr == NULL || TempListedSubStr == NULL ) {
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  for ( Status = FileHandleFindFirstFile(Dir, &FileInfo)
      ; !EFI_ERROR(Status) && !NoFile
      ; Status = FileHandleFindNextFile(Dir, FileInfo, &NoFile)
     ){

    //
    // Skip file with mismatching File attribute
    //
    if ((FileInfo->Attribute & (FileAttr)) == 0) {
      continue;
    }

    NewFileInfoEntry = NULL;
    NewFileInfoEntry = (FILE_INFO_ENTRY*)AllocateZeroPool(sizeof(FILE_INFO_ENTRY));
    if (NewFileInfoEntry == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }
    NewFileInfoEntry->Signature = FILE_INFO_SIGNATURE;
    NewFileInfoEntry->FileInfo  = AllocateCopyPool(FileInfo->Size, FileInfo);
    if (NewFileInfoEntry->FileInfo == NULL) {
      FreePool(NewFileInfoEntry);
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }

    NewFileInfoEntry->FnFirstPart  = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);
    if (NewFileInfoEntry->FnFirstPart == NULL) {
      FreePool(NewFileInfoEntry->FileInfo);
      FreePool(NewFileInfoEntry);
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }
    NewFileInfoEntry->FnSecondPart = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);
    if (NewFileInfoEntry->FnSecondPart == NULL) {
      FreePool(NewFileInfoEntry->FileInfo);
      FreePool(NewFileInfoEntry->FnFirstPart);
      FreePool(NewFileInfoEntry);
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }

    //
    // Splitter the whole New file name into 2 parts between the last period L'.' into NewFileName NewFileExtension 
    // If no period in the whole file name. NewFileExtension is set to L'\0' 
    //
    NewFileName          = NewFileInfoEntry->FnFirstPart;
    NewFileNameExtension = NewFileInfoEntry->FnSecondPart;
    SplitFileNameExtension(FileInfo->FileName, NewFileName, NewFileNameExtension);
    UpperCaseString(NewFileName);
    UpperCaseString(NewFileNameExtension);

    //
    // Insert capsule file in alphabetical ordered list
    //
    for (Link = FileInfoList->ForwardLink; Link != FileInfoList; Link = Link->ForwardLink) {
      //
      // Get the FileInfo from the link list
      //
      TempFileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
      ListedFileName          = TempFileInfoEntry->FnFirstPart;
      ListedFileNameExtension = TempFileInfoEntry->FnSecondPart;

      //
      // Follow rule in UEFI spec 8.5.5 to compare file name 
      //
      IndexListed = 0;
      IndexNew    = 0;
      while (TRUE){
        //
        // First compare each substrings in NewFileName & ListedFileName between periods
        //
        GetSubStringBeforePeriod(&NewFileName[IndexNew], TempNewSubStr, &NewSubStrLen);
        GetSubStringBeforePeriod(&ListedFileName[IndexListed], TempListedSubStr, &ListedSubStrLen);
        if (NewSubStrLen > ListedSubStrLen) {
          //
          // Substr in NewFileName is longer.  Pad tail with SPACE
          //
          PadStrInTail(TempListedSubStr, NewSubStrLen - ListedSubStrLen, L' ');
        } else if (NewSubStrLen < ListedSubStrLen){
          //
          // Substr in ListedFileName is longer. Pad tail with SPACE
          //
          PadStrInTail(TempNewSubStr, ListedSubStrLen - NewSubStrLen, L' ');
        }

        SubStrCmpResult = StrnCmp(TempNewSubStr, TempListedSubStr, MAX_FILE_NAME_LEN);
        if (SubStrCmpResult != 0) {
          break;
        }

        //
        // Move to skip this substring
        //
        IndexNew    += NewSubStrLen;
        IndexListed += ListedSubStrLen;
        //
        // Reach File First Name end
        //
        if (NewFileName[IndexNew] == L'\0' || ListedFileName[IndexListed] == L'\0') {
          break;
        }

        //
        // Skip the period L'.'
        //
        IndexNew++;
        IndexListed++;

      }

      if (SubStrCmpResult < 0) {
        //
        // NewFileName is smaller. Find the right place to insert New file
        // 
        break;
      } else if (SubStrCmpResult == 0) {
        // 
        // 2 cases whole NewFileName is smaller than ListedFileName
        //   1. if NewFileName == ListedFileName. Continue to compare FileNameExtension
        //   2. if NewFileName is shorter than ListedFileName
        //
        if (NewFileName[IndexNew] == L'\0') {
          if (ListedFileName[IndexListed] != L'\0' || (StrnCmp(NewFileNameExtension, ListedFileNameExtension, MAX_FILE_NAME_LEN) < 0)) {
            break;
          } 
        }
      }

      //
      // Other case, ListedFileName is smaller. Continue to compare the next file in the list
      //
    }

    //
    // If Find an entry in the list whose name is bigger than new FileInfo in alphabet order
    //    Insert it before this entry
    // else 
    //    Insert at the tail of this list (Link = FileInfoList)
    //
    InsertTailList(Link, &NewFileInfoEntry->Link);

    FileCount++;
  }

  *FileNum = FileCount;

EXIT:
  
  if (TempNewSubStr != NULL) {
    FreePool(TempNewSubStr);
  }

  if (TempListedSubStr != NULL) {
    FreePool(TempListedSubStr);
  }


  if (EFI_ERROR(Status)) {
    while(!IsListEmpty(FileInfoList)) {
      Link = FileInfoList->ForwardLink; 
      RemoveEntryList(Link);

      TempFileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
      
      FreePool(TempFileInfoEntry->FileInfo);
      FreePool(TempFileInfoEntry->FnFirstPart);
      FreePool(TempFileInfoEntry->FnSecondPart);
      FreePool(TempFileInfoEntry);
    }
    *FileNum = 0;
  }

  return Status;

}


/**

  This routine is called to get all qualified image from file from an given directory 
  in alphabetic order. All the file image is copied to allocated boottime memory. 
  Caller should free these memory

  @param[in]  Dir            Directory file handler 
  @param[in]  FileAttr       Attribute of file to be red from directory
  @param[out] FilePtr        File images Info buffer red from directory 
  @param[out] FileNum        File images number red from directory

  @retval EFI_SUCCESS

**/
EFI_STATUS
GetFileImageInAlphabetFromDir(
  IN EFI_FILE_HANDLE   Dir,
  IN UINT64            FileAttr,
  OUT IMAGE_INFO       **FilePtr,
  OUT UINTN            *FileNum
  )
{
  EFI_STATUS            Status;
  LIST_ENTRY            *Link;
  EFI_FILE_HANDLE       FileHandle;
  FILE_INFO_ENTRY       *FileInfoEntry;
  EFI_FILE_INFO         *FileInfo;
  UINTN                 FileCount;
  IMAGE_INFO            *TempFilePtrBuf;
  UINTN                 Size;
  LIST_ENTRY            FileInfoList;

  FileHandle       = NULL;
  FileCount        = 0;
  TempFilePtrBuf   = NULL;
  *FilePtr         = NULL;

  //
  // Get file list in Dir in alphabetical order
  //
  Status = GetFileInfoListInAlphabetFromDir(
             Dir, 
             FileAttr,
             &FileInfoList, 
             &FileCount
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "GetFileInfoListInAlphabetFromDir Failed!\n"));
    goto EXIT;
  }

  if (FileCount == 0) {
    DEBUG ((EFI_D_ERROR, "No file found in Dir!\n"));
    Status = EFI_NOT_FOUND;
    goto EXIT;
  }

  TempFilePtrBuf = (IMAGE_INFO *)AllocateZeroPool(sizeof(IMAGE_INFO) * FileCount);
  if (TempFilePtrBuf == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  //
  // Read all files from FileInfoList to BS memory 
  //
  FileCount = 0;
  for (Link = FileInfoList.ForwardLink; Link != &FileInfoList; Link = Link->ForwardLink) {
    //
    // Get FileInfo from the link list
    //
    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
    FileInfo      = FileInfoEntry->FileInfo;

    Status = Dir->Open(
                    Dir,
                    &FileHandle,
                    FileInfo->FileName,
                    EFI_FILE_MODE_READ,
                    0
                    );
    if (EFI_ERROR(Status)){
      continue;
    }

    Size = (UINTN)FileInfo->FileSize;
    TempFilePtrBuf[FileCount].ImageAddress = AllocateZeroPool(Size);
    if (TempFilePtrBuf[FileCount].ImageAddress == NULL) {
      DEBUG((DEBUG_ERROR, "Fail to allocate memory for capsule. Stop processing the rest.\n"));
      break;
    }

    Status = FileHandle->Read(
                           FileHandle,
                           &Size,
                           TempFilePtrBuf[FileCount].ImageAddress
                           );
 
    FileHandle->Close(FileHandle);

    //
    // Skip read error file
    //
    if (EFI_ERROR(Status) || Size != (UINTN)FileInfo->FileSize) {
      //
      // Remove this error file info accordingly
      // & move Link to BackLink
      //
      Link = RemoveEntryList(Link);
      Link = Link->BackLink;

      FreePool(FileInfoEntry->FileInfo);
      FreePool(FileInfoEntry->FnFirstPart);
      FreePool(FileInfoEntry->FnSecondPart);
      FreePool(FileInfoEntry);
  
      FreePool(TempFilePtrBuf[FileCount].ImageAddress);
      TempFilePtrBuf[FileCount].ImageAddress = NULL;
      TempFilePtrBuf[FileCount].FileInfo     = NULL;

      continue;
    }
    TempFilePtrBuf[FileCount].FileInfo = FileInfo;
    FileCount++;
  }

  
  DEBUG_CODE (
    for (Link = FileInfoList.ForwardLink; Link != &FileInfoList; Link = Link->ForwardLink) {
      FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
      FileInfo      = FileInfoEntry->FileInfo;
      DEBUG((DEBUG_INFO, "Successfully read capsule file %s from disk.\n", FileInfo->FileName));
    }
    );

EXIT:

  *FilePtr = TempFilePtrBuf;
  *FileNum = FileCount;

  while(!IsListEmpty(&FileInfoList)) {
    Link = FileInfoList.ForwardLink; 
    RemoveEntryList(Link);

    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);

    FreePool(FileInfoEntry->FileInfo);
    FreePool(FileInfoEntry->FnFirstPart);
    FreePool(FileInfoEntry->FnSecondPart);
    FreePool(FileInfoEntry);
  }

  return Status;
}

/**

  This routine is called to remove all qualified image from file from an given directory. 

  @param[in] Dir                  Directory file handler 
  @param[in] FileAttr             Attribute of files to be deleted

  @retval EFI_SUCCESS

**/
EFI_STATUS
RemoveFileFromDir(
  IN EFI_FILE_HANDLE   Dir,
  IN UINT64            FileAttr
  )
{
  EFI_STATUS        Status;
  LIST_ENTRY        *Link;
  LIST_ENTRY        FileInfoList;
  EFI_FILE_HANDLE   FileHandle;
  FILE_INFO_ENTRY   *FileInfoEntry;
  EFI_FILE_INFO     *FileInfo;
  UINTN             FileCount;

  FileHandle = NULL;

  //
  // Get file list in Dir in alphabetical order
  //
  Status = GetFileInfoListInAlphabetFromDir(
             Dir,
             FileAttr,
             &FileInfoList, 
             &FileCount
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "GetFileInfoListInAlphabetFromDir Failed!\n"));
    goto EXIT;
  }

  if (FileCount == 0) {
    DEBUG ((EFI_D_ERROR, "No file found in Dir!\n"));
    Status = EFI_NOT_FOUND;
    goto EXIT;
  }

  //
  // Delete all file with given attribute in Dir 
  //
  for (Link = FileInfoList.ForwardLink; Link != &(FileInfoList); Link = Link->ForwardLink) {
    //
    // Get FileInfo from the link list
    //
    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
    FileInfo      = FileInfoEntry->FileInfo;

    Status = Dir->Open(
                    Dir,
                    &FileHandle,
                    FileInfo->FileName,
                    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                    0
                    );
    if (EFI_ERROR(Status)){
      continue;
    }

    Status = FileHandle->Delete(FileHandle);
  }

EXIT:

  while(!IsListEmpty(&FileInfoList)) {
    Link = FileInfoList.ForwardLink;
    RemoveEntryList(Link);

    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
    
    FreePool(FileInfoEntry->FileInfo);
    FreePool(FileInfoEntry);
  }

  return Status;
}

BOOLEAN
CodLibCheckCapsuleOnDiskFlag(
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

/**

   This routine is called to get all caspules from file. The capsule file image is 
   copied to BS memory. Caller is responsible to free them.
  
  @param[out]   CapsulePtr           Copied Capsule file Image Info buffer
  @param[out]   CapsuleNum           CapsuleNumber

  @retval EFI_SUCCESS

**/
EFI_STATUS  
CodLibGetAllCapsuleOnDisk(
  IN  UINTN         MaxRetryCount,
  OUT IMAGE_INFO    **CapsulePtr,
  OUT UINTN         *CapsuleNum
  )
{
  EFI_STATUS                       Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_HANDLE                  RootDir;
  EFI_FILE_HANDLE                  FileDir;

  Fs          = NULL;
  RootDir     = NULL;
  FileDir     = NULL;
  *CapsuleNum = 0;

  Status = GetEfiSysPartitionFromActiveBootOption(MaxRetryCount, NULL, &Fs);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = Fs->OpenVolume(Fs, &RootDir);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = RootDir->Open(
                      RootDir,
                      &FileDir,
                      EFI_CAPSULE_FROM_FILE_DIR,
                      EFI_FILE_MODE_READ,
                      0
                      );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "CodLibGetAllCapsuleOnDisk fail to open RootDir!\n"));
    goto EXIT;
  }

  //
  // Only Load files with EFI_FILE_SYSTEM or EFI_FILE_ARCHIVE attribute
  // ignore EFI_FILE_READ_ONLY, EFI_FILE_HIDDEN, EFI_FILE_RESERVED, EFI_FILE_DIRECTORY
  //
  Status = GetFileImageInAlphabetFromDir(
             FileDir,
             EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE,
             CapsulePtr,
             CapsuleNum
             );
  DEBUG((DEBUG_INFO, "GetFileImageInAlphabetFromDir status %x\n", Status));
  
  //
  // Always remove file to avoid deadloop in capsule process
  //
  Status = RemoveFileFromDir(FileDir, EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE);
  DEBUG((DEBUG_INFO, "RemoveFileFromDir status %x\n", Status));

EXIT:

  if (FileDir != NULL) {
    FileDir->Close (FileDir);
  }

  if (RootDir != NULL) {
    RootDir->Close (RootDir);
  }

  return Status;
}


/*
Reset OsIndication File Capsule Delivery Supported Flag
and clear the boot next variable.
*/
EFI_STATUS
CoDLibClearCapsuleOnDiskFlag(
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
  DataSize = sizeof(UINT64);
  Status = gRT->GetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &DataSize,
                  &OsIndication
                  );
  if (EFI_ERROR(Status) || 
      (OsIndication & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) == 0) {
    return Status;
  }

  OsIndication &= ~((UINT64)EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED);
  Status = gRT->SetVariable (
                  L"OsIndications",
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  sizeof(UINT64),
                  &OsIndication
                  );
  ASSERT(!EFI_ERROR(Status));

  //
  // Delete BootNext variable. Capsule Process may reset system, so can't rely on Bds to clear this variable 
  //
  Status = gRT->SetVariable (
                  EFI_BOOT_NEXT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  0,
                  0,
                  NULL
                  );
  ASSERT (Status == EFI_SUCCESS || Status == EFI_NOT_FOUND);

  return EFI_SUCCESS;
}
