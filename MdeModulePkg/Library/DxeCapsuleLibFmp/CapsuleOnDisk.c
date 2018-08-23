/** @file
  The implementation supports Capusle on Disk.

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "CapsuleOnDisk.h"

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
GetBootOptionInOrder(
  OUT EFI_BOOT_MANAGER_LOAD_OPTION **OptionBuf,
  OUT UINTN                        *OptionCount
  )
{
  EFI_STATUS                   Status;
  UINTN                        DataSize;
  UINT16                       BootNext;
  CHAR16                       BootOptionName[20];
  EFI_BOOT_MANAGER_LOAD_OPTION *BootOrderOptionBuf;
  UINTN                        BootOrderCount;
  EFI_BOOT_MANAGER_LOAD_OPTION BootNextOptionEntry;
  UINTN                        BootNextCount;
  EFI_BOOT_MANAGER_LOAD_OPTION *TempBuf;

  BootOrderOptionBuf  = NULL;
  TempBuf             = NULL;
  BootNextCount       = 0;
  BootOrderCount      = 0;
  *OptionBuf          = NULL;
  *OptionCount        = 0;

  //
  // First Get BootOption from "BootNext"
  //
  DataSize = sizeof(BootNext);
  Status = gRT->GetVariable (
                  L"BootNext",
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &DataSize,
                  (VOID *)&BootNext
                  );
  //
  // BootNext variable is a single UINT16
  //
  if (!EFI_ERROR(Status) && DataSize == sizeof(UINT16)) {
    //
    // Add the boot next boot option
    //
    UnicodeSPrint (BootOptionName, sizeof (BootOptionName), L"Boot%04x", BootNext);
    ZeroMem(&BootNextOptionEntry, sizeof(EFI_BOOT_MANAGER_LOAD_OPTION));
    Status = EfiBootManagerVariableToLoadOption (BootOptionName, &BootNextOptionEntry);

    if (!EFI_ERROR(Status)) {
      BootNextCount = 1;
    }
  }

  //
  // Second get BootOption from "BootOrder"
  //
  BootOrderOptionBuf = EfiBootManagerGetLoadOptions (&BootOrderCount, LoadOptionTypeBoot);
  if (BootNextCount == 0 && BootOrderCount == 0) {
    return EFI_NOT_FOUND;
  }

  //
  // At least one BootOption is found
  //

  TempBuf = AllocatePool(sizeof(EFI_BOOT_MANAGER_LOAD_OPTION) * (BootNextCount + BootOrderCount));
  if (TempBuf != NULL) {
    if (BootNextCount == 1) {
      CopyMem(TempBuf, &BootNextOptionEntry, sizeof(EFI_BOOT_MANAGER_LOAD_OPTION));
    }

    if (BootOrderCount > 0) {
      CopyMem(TempBuf + BootNextCount, BootOrderOptionBuf, sizeof(EFI_BOOT_MANAGER_LOAD_OPTION) * BootOrderCount);
    }

    *OptionBuf   = TempBuf;
    *OptionCount = BootNextCount + BootOrderCount;
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_OUT_OF_RESOURCES;
  }

  FreePool(BootOrderOptionBuf);

  return Status;
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

  @param[in]  MaxRetry    Max Connection Retry. Stall 100ms between each connection try to ensure
                          device like USB can get enumerated.
  @param[out] Fs          Simple File System Protocol found on first active EFI system partition

  @retval EFI_SUCCESS     Simple File System protocol found for EFI system partition
  @retval EFI_NOT_FOUND   No Simple File System protocol found for EFI system partition

**/
EFI_STATUS 
GetEfiSysPartitionFromActiveBootOption(
  IN  UINTN                            MaxRetry,
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  **Fs
  )
{
  EFI_STATUS                   Status;
  EFI_BOOT_MANAGER_LOAD_OPTION *BootOptionBuf;
  UINTN                        BootOptionNum;
  UINTN                        Index;
  EFI_DEVICE_PATH_PROTOCOL     *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL     *CurFullPath;
  EFI_DEVICE_PATH_PROTOCOL     *PreFullPath;

  *Fs = NULL;

  Status = GetBootOptionInOrder(&BootOptionBuf, &BootOptionNum);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "GetBootOptionInOrder Failed %x! No BootOption available for connection\n", Status));
    return Status;
  }

  //
  // Search BootOptionList to check if it is an active boot option with EFI system partition
  //  1. Connect device path
  //  2. expend short/plug in devicepath
  //  3. LoadImage
  //
  for (Index = 0; Index < BootOptionNum; Index++) {
    //
    // Get the boot option from the link list
    //
    DevicePath  = BootOptionBuf[Index].FilePath;

    //
    // Skip inactive or  legacy boot options
    //
    if ((BootOptionBuf[Index].Attributes & LOAD_OPTION_ACTIVE) == 0 ||
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

    CurFullPath = NULL;
    //
    // Try every full device Path generated from bootoption 
    //
    do {
      PreFullPath = CurFullPath;
      CurFullPath = EfiBootManagerGetNextFullDevicePath(DevicePath, CurFullPath);

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
        CHAR16 *DevicePathStr1;
 
        DevicePathStr1 = ConvertDevicePathToText(CurFullPath, TRUE, TRUE);
        if (DevicePathStr1 != NULL){
          DEBUG((DEBUG_INFO, "Full device path %s\n", DevicePathStr1));
          FreePool(DevicePathStr1);
        } 
      );

      //
      // Make sure the boot option device path connected.
      // Only handle first device in boot option. Other optional device paths are described as OSV specific
      // FullDevice could contain extra directory & file info. So don't check connection status here.
      //
      EfiBootManagerConnectDevicePath (CurFullPath, NULL);
      Status = GetEfiSysPartitionFromDevPath(CurFullPath, Fs);

      //
      // Some relocation device like USB need more time to get enumerated
      //
      while (EFI_ERROR(Status) && MaxRetry > 0) {
        EfiBootManagerConnectDevicePath(CurFullPath, NULL);

        //
        // Search for EFI system partition protocol on full device path in Boot Option 
        //
        Status = GetEfiSysPartitionFromDevPath(CurFullPath, Fs);
        if (!EFI_ERROR(Status)) {
          break;
        }
        DEBUG((DEBUG_ERROR, "GetEfiSysPartitionFromDevPath Loop %x\n", Status));
        //
        // Stall 100ms if connection failed to ensure USB stack is ready.
        //
        gBS->Stall(100000);
        MaxRetry --;
      }
    } while(EFI_ERROR(Status));

    //
    // Find a qualified Simple File System
    //
    if (!EFI_ERROR(Status)) {
      break;
    }

  }

  //
  // No qualified EFI system partition found
  //
  if (*Fs == NULL) {
    Status = EFI_NOT_FOUND;
  }

  DEBUG_CODE (
    CHAR16 *DevicePathStr2;
    if (*Fs != NULL) {
      DevicePathStr2 = ConvertDevicePathToText(CurFullPath, TRUE, TRUE);
      if (DevicePathStr2 != NULL){
        DEBUG((DEBUG_INFO, "Found Active EFI System Partion on %s\n", DevicePathStr2));
        FreePool(DevicePathStr2);
      } 
    } else {
      DEBUG((DEBUG_INFO, "Failed to found Active EFI System Partion\n"));
    }
  );

  if (CurFullPath != NULL) {
    FreePool(CurFullPath);
  }

  //
  // Free BootOption Buffer
  //
  for (Index = 0; Index < BootOptionNum; Index++) {
    if (BootOptionBuf[Index].Description != NULL) {
      FreePool(BootOptionBuf[Index].Description);
    }

    if (BootOptionBuf[Index].FilePath != NULL) {
      FreePool(BootOptionBuf[Index].FilePath);
    }

    if (BootOptionBuf[Index].OptionalData != NULL) {
      FreePool(BootOptionBuf[Index].OptionalData);
    }
  }

  FreePool(BootOptionBuf);

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

    NewFileInfoEntry->FileNameFirstPart  = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);
    if (NewFileInfoEntry->FileNameFirstPart == NULL) {
      FreePool(NewFileInfoEntry->FileInfo);
      FreePool(NewFileInfoEntry);
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }
    NewFileInfoEntry->FileNameSecondPart = (CHAR16 *) AllocateZeroPool(MAX_FILE_NAME_SIZE);
    if (NewFileInfoEntry->FileNameSecondPart == NULL) {
      FreePool(NewFileInfoEntry->FileInfo);
      FreePool(NewFileInfoEntry->FileNameFirstPart);
      FreePool(NewFileInfoEntry);
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }

    //
    // Splitter the whole New file name into 2 parts between the last period L'.' into NewFileName NewFileExtension 
    // If no period in the whole file name. NewFileExtension is set to L'\0' 
    //
    NewFileName          = NewFileInfoEntry->FileNameFirstPart;
    NewFileNameExtension = NewFileInfoEntry->FileNameSecondPart;
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
      ListedFileName          = TempFileInfoEntry->FileNameFirstPart;
      ListedFileNameExtension = TempFileInfoEntry->FileNameSecondPart;

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
      FreePool(TempFileInfoEntry->FileNameFirstPart);
      FreePool(TempFileInfoEntry->FileNameSecondPart);
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
      FreePool(FileInfoEntry->FileNameFirstPart);
      FreePool(FileInfoEntry->FileNameSecondPart);
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

  //
  // FileInfo will be freed by Calller
  //
  while(!IsListEmpty(&FileInfoList)) {
    Link = FileInfoList.ForwardLink; 
    RemoveEntryList(Link);

    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);

    FreePool(FileInfoEntry->FileNameFirstPart);
    FreePool(FileInfoEntry->FileNameSecondPart);
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
  // Delete all files with given attribute in Dir 
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

/**

  This routine is called to get all caspules from file. The capsule file image is
  copied to BS memory. Caller is responsible to free them.

  @param[in]    MaxRetry             Max Connection Retry. Stall 100ms between each connection try to ensure
                                     devices like USB can get enumerated.
  @param[out]   CapsulePtr           Copied Capsule file Image Info buffer
  @param[out]   CapsuleNum           CapsuleNumber

  @retval EFI_SUCCESS

**/
EFI_STATUS
EFIAPI
GetAllCapsuleOnDisk(
  IN  UINTN         MaxRetry,
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

  Status = GetEfiSysPartitionFromActiveBootOption(MaxRetry, &Fs);
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

/**

  This routine is called to check if CapsuleOnDisk flag in OsIndications Variable
  is enabled.

  @retval TRUE     Flag is enabled
          FALSE    Flag is not enabled

**/
BOOLEAN
EFIAPI
CoDCheckCapsuleOnDiskFlag(
  VOID
  )
{
  EFI_STATUS            Status;
  UINT64                OsIndication;
  UINTN                 DataSize;

  //
  // Check File Capsule Delivery Supported Flag in OsIndication variable
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

  This routine is called to clear CapsuleOnDisk flags including OsIndications and BootNext variable

  @retval EFI_SUCCESS   All Capsule On Disk flags are cleared

**/
EFI_STATUS
CoDClearCapsuleOnDiskFlag(
  VOID
  )
{
  EFI_STATUS            Status;
  UINT64                OsIndication;
  UINTN                 DataSize;

  //
  // Reset File Capsule Delivery Supported Flag in OsIndication variable
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

/**

  This routine is called to clear Capsule On Disk Relocation flag
  The flag is the total size of capsules being relocated. It is saved
  in CapsuleOnDisk Relocation Info varible in form of UINT64

  @retval EFI_SUCCESS   Capsule Relocation flag is cleared

**/
EFI_STATUS
EFIAPI
CoDCheckCapsuleRelocationInfo(
  OUT UINT64 *RelocTotalSize
  )
{
  EFI_STATUS  Status;
  UINTN       DataSize;

  DataSize        = sizeof(UINT64);
  *RelocTotalSize = 0;

  Status= gRT->GetVariable (
                COD_RELOCATION_INFO_VAR_NAME,
                &gEfiCapsuleVendorGuid,
                NULL,
                &DataSize,
                RelocTotalSize
                );

  if (DataSize != sizeof(UINT64)) {
   return EFI_INVALID_PARAMETER;
  }

  return Status;
}

/**

  This routine is called to clear CapsuleOnDisk Relocation Info variable.
  Total Capsule On Disk length is recorded in this variable

  @retval EFI_SUCCESS   Capsule On Disk flags are cleared

**/
EFI_STATUS
CoDClearCapsuleRelocationInfo(
  VOID
  )
{
  return gRT->SetVariable (
                COD_RELOCATION_INFO_VAR_NAME,
                &gEfiCapsuleVendorGuid,
                0,
                0,
                NULL
                );
}

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
  )
{
  EFI_STATUS               Status;
  UINTN                    Index;
  UINTN                    VarSize;
  EFI_HANDLE               Handle;
  EFI_DISK_IO_PROTOCOL     *DiskIo;
  EFI_BLOCK_IO_PROTOCOL    *BlockIo;
  UINT64                   CapsuleTotalSize;
  UINT8                    *CapsuleDataBuf;
  UINT8                    *CapsuleDataBufEnd;
  UINT8                    *CapsulePtr;
  EFI_PHYSICAL_ADDRESS     *TempCapsuleBufPtr;
  UINTN                    TempCapsuleNum;
  UINTN                    TempCapsuleSize;
  EFI_DEVICE_PATH_PROTOCOL *CurFullPath;

  DEBUG ((DEBUG_INFO, "CodLibRetrieveRelocatedCapsuleOnDisk enter\n"));

  TempCapsuleBufPtr = NULL;
  CapsuleDataBuf    = NULL;
  *CapsuleBufPtr    = NULL;
  *CapsuleNum       = 0;

  //
  // Get Capsule On Disk Size from NV Storage
  //
  VarSize = sizeof (UINT64);
  Status  = gRT->GetVariable(
                   COD_RELOCATION_INFO_VAR_NAME, 
                   &gEfiCapsuleVendorGuid,
                   NULL,
                   &VarSize,
                   &CapsuleTotalSize
                   );
  if (EFI_ERROR(Status) || VarSize != sizeof (UINT64)) {
    return EFI_NOT_FOUND;
  }

  //
  // Relocation Device should be a low lever block IO device specified by platform.
  // It is connected within TCB, therefore connection strictly follows full device path
  // Platform must also ensure no option rom is needed in such device connection
  //
  CurFullPath = (EFI_DEVICE_PATH *)PcdGetPtr(PcdCodRelocationDevPath);
  Status = EfiBootManagerConnectDevicePath (CurFullPath, &Handle);

  //
  // Loop to wait for relocation device to get enumerated
  //
  while (EFI_ERROR(Status) && MaxRetry > 0) {
    Status = EfiBootManagerConnectDevicePath(CurFullPath, &Handle);

    //
    // Stall 100ms if connection failed to ensure USB stack is ready.
    //
    gBS->Stall(100000);
    MaxRetry --;
  }

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "CodLibRetrieveRelocatedCapsuleOnDisk fail to find relocation device!\n"));
    return Status;
  }

  Status = gBS->HandleProtocol(Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "CodLibRetrieveRelocatedCapsuleOnDisk fail to locate BlockIo!\n"));
    return Status;
  }

  Status = gBS->HandleProtocol(Handle, &gEfiDiskIoProtocolGuid, (VOID **)&DiskIo);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  CapsuleDataBuf = AllocatePool((UINTN)CapsuleTotalSize);
  if (CapsuleDataBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Overflow check
  //
  if (MAX_ADDRESS - (PHYSICAL_ADDRESS)CapsuleDataBuf <= CapsuleTotalSize) {
    Status = EFI_INVALID_PARAMETER;
    goto EXIT;
  }
  CapsuleDataBufEnd = CapsuleDataBuf + CapsuleTotalSize; 

  //
  // Read all relocated capsule on disk into memory
  //
  Status = DiskIo->ReadDisk(DiskIo, BlockIo->Media->MediaId, 0, (UINTN)CapsuleTotalSize, CapsuleDataBuf);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "DiskRead Error! Status = %x\n", Status));
    goto EXIT;
  }

  //
  // More integrity check against Capsule Header to ensure no data corruption in NV Var & Relocation storage
  //
  CapsulePtr = CapsuleDataBuf;
  Index      = 0;
  do {
    //
    // Overflow check
    //
    if ((MAX_ADDRESS - (PHYSICAL_ADDRESS)CapsulePtr) < ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize ||
        (CapsuleDataBufEnd - CapsulePtr) < sizeof(EFI_CAPSULE_HEADER)) {
      Status = EFI_INVALID_PARAMETER;
      goto EXIT;
    }

    CapsulePtr += ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize;
    Index++;
  } while (CapsulePtr < CapsuleDataBufEnd);

  if (CapsulePtr > CapsuleDataBufEnd) {
    Status = EFI_INVALID_PARAMETER;
    goto EXIT;
  }

  TempCapsuleBufPtr = AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS) * Index);
  if (TempCapsuleBufPtr == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }
  TempCapsuleNum = Index;

  //
  // Re-iterate the capsule buffer to get each relocated capsule starting address
  //
  for (Index = 0, CapsulePtr = CapsuleDataBuf; CapsulePtr < CapsuleDataBufEnd && Index < TempCapsuleNum; Index++) {
    //
    // Make sure relocated capsules are aligned
    //
    TempCapsuleSize          = ((EFI_CAPSULE_HEADER *)CapsulePtr)->CapsuleImageSize;
    TempCapsuleBufPtr[Index] = (EFI_PHYSICAL_ADDRESS)AllocatePages(EFI_SIZE_TO_PAGES(TempCapsuleSize));
    if (TempCapsuleBufPtr[Index] == (EFI_PHYSICAL_ADDRESS)NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }
    CopyMem((VOID *)TempCapsuleBufPtr[Index], CapsulePtr, TempCapsuleSize);
    CapsulePtr += TempCapsuleSize;
  }

  *CapsuleBufPtr = TempCapsuleBufPtr;
  *CapsuleNum    = Index;

  DEBUG_CODE (
    CHAR16 *RelocateDevPathStr;
    UINTN  CapIndex;

    RelocateDevPathStr = ConvertDevicePathToText(CurFullPath, TRUE, TRUE);

    if (RelocateDevPathStr != NULL){
      DEBUG((DEBUG_INFO, "%d Capsule found in Relocated device\n", *CapsuleNum));
      DEBUG((DEBUG_INFO, "%s\n", RelocateDevPathStr));
      FreePool(RelocateDevPathStr);
    } else {
      DEBUG((DEBUG_INFO, "%d Capsule found in Relocated device\n", *CapsuleNum));
    }

    for (CapIndex = 0; CapIndex < *CapsuleNum; CapIndex++) {
      DEBUG((DEBUG_INFO, "%d Capsule image size 0x%x loaded in 0x%x\n", 
             CapIndex, ((EFI_CAPSULE_HEADER *)TempCapsuleBufPtr[CapIndex])->CapsuleImageSize, TempCapsuleBufPtr[CapIndex]));
    }
  );

EXIT:
  if (EFI_ERROR(Status)) {
    if (TempCapsuleBufPtr != NULL) {
      for (Index = 0; Index < TempCapsuleNum; Index++) {
        if (TempCapsuleBufPtr[Index] != (EFI_PHYSICAL_ADDRESS)NULL) {
          FreePool((VOID *)TempCapsuleBufPtr[Index]);
        }
      }

      FreePool(TempCapsuleBufPtr);
    }
  }

  if (CapsuleDataBuf != NULL) {
    FreePool(CapsuleDataBuf);
  }

  return Status;
}

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
  )
{
  EFI_STATUS               Status;
  UINTN                    CapsuleOnDiskNum;
  UINTN                    Index;
  UINT64                   CapsuleTotalSize;
  IMAGE_INFO               *CapsuleOnDiskBuf;
  EFI_HANDLE               Handle;
  EFI_DISK_IO_PROTOCOL     *DiskIo;
  EFI_BLOCK_IO_PROTOCOL    *BlockIo;
  UINT8                    *CapsuleDataBuf;
  UINT8                    *CapsulePtr;

  Status = GetAllCapsuleOnDisk(MaxRetry, &CapsuleOnDiskBuf, &CapsuleOnDiskNum);
  DEBUG ((DEBUG_INFO, "GetAllCapsuleOnDisk Status - 0x%x\n", Status));

  //
  // Make sure boot option device path connected.
  // Only handle first device in boot option. Other optional device paths are described as OSV specific
  // FullDevice could contain extra directory & file info. So don't check connection status here.
  //
  EfiBootManagerConnectDevicePath ((EFI_DEVICE_PATH *)PcdGetPtr(PcdCodRelocationDevPath), &Handle);

  Status = gBS->HandleProtocol(Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
  if (EFI_ERROR(Status) || BlockIo->Media->ReadOnly) {
    DEBUG((DEBUG_ERROR, "Fail to find Capsule on Disk relocation BlockIo device or device is ReadOnly!\n"));
    return Status;
  }

  Status = gBS->HandleProtocol(Handle, &gEfiDiskIoProtocolGuid, (VOID **)&DiskIo);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // Check if device used to relocate Capsule On Disk is big enough
  //
  for (Index = 0, CapsuleTotalSize = 0; Index < CapsuleOnDiskNum; Index++) {
    //
    // Overflow check
    //
    if (MAX_ADDRESS - CapsuleTotalSize <= CapsuleOnDiskBuf[Index].FileInfo->FileSize) {
      return EFI_INVALID_PARAMETER;
    }
    CapsuleTotalSize += CapsuleOnDiskBuf[Index].FileInfo->FileSize;
  }

  DEBUG((DEBUG_INFO, "CapsuleTotalSize %x\n", CapsuleTotalSize));
  //
  // Check if CapsuleTotalSize. There could be reminder, so use LastBlock number directly
  //
  if (DivU64x32(CapsuleTotalSize, BlockIo->Media->BlockSize) >  BlockIo->Media->LastBlock) {
    DEBUG((DEBUG_ERROR, "Relocation device isn't big enough to hold all Capsule on Disk!\n"));
    DEBUG((DEBUG_ERROR, "CapsuleTotalSize = %x\n", CapsuleTotalSize));
    DEBUG((DEBUG_ERROR, "RelocationDev BlockSize = %x LastBlock = %x\n", BlockIo->Media->BlockSize, BlockIo->Media->LastBlock));
    return EFI_OUT_OF_RESOURCES;
  }

  CapsuleDataBuf = AllocatePool((UINTN)CapsuleTotalSize);
  if (CapsuleDataBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  //
  // Try to line up all the Capsule on Disk and write to relocation disk at one time. It could save some time in disk write
  //
  for (Index = 0, CapsulePtr = CapsuleDataBuf; Index < CapsuleOnDiskNum; Index++) {
    CopyMem(CapsulePtr, CapsuleOnDiskBuf[Index].ImageAddress, CapsuleOnDiskBuf[Index].FileInfo->FileSize);
    CapsulePtr += CapsuleOnDiskBuf[Index].FileInfo->FileSize;
  }

  Status = DiskIo->WriteDisk(DiskIo, BlockIo->Media->MediaId, 0, (UINTN)CapsuleTotalSize, CapsuleDataBuf);

  if (!EFI_ERROR(Status)) {
    //
    // Save Capsule On Disk Size to NV Storage
    //
    Status = gRT->SetVariable(
                    COD_RELOCATION_INFO_VAR_NAME, 
                    &gEfiCapsuleVendorGuid, 
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                    sizeof (UINT64),
                    &CapsuleTotalSize
                    );
  } else {
    DEBUG((DEBUG_ERROR, "RelocateCapsuleOnDisk WriteDisk error %x\n", Status));
  }

  FreePool(CapsuleDataBuf);

  //
  // Free resources allocated by CodLibGetAllCapsuleOnDisk
  //
  for (Index = 0; Index < CapsuleOnDiskNum; Index++ ) {
    FreePool(CapsuleOnDiskBuf[Index].ImageAddress);
    FreePool(CapsuleOnDiskBuf[Index].FileInfo);
  }
  FreePool(CapsuleOnDiskBuf);

  return Status;
}


