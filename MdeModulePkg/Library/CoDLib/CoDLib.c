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
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileSystemInfo.h>
#include <Library/CapsuleLib.h>
#include <Library/CoDLib.h>
#include <Library/DevicePathLib.h>

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


/** Retrieve first entry from a directory.

  This function takes an open directory handle and gets information from the
  first entry in the directory.  A buffer is allocated to contain
  the information and a pointer to the buffer is returned in *Buffer.  The
  caller can use FileHandleFindNextFile() to get subsequent directory entries.

  The buffer will be freed by FileHandleFindNextFile() when the last directory
  entry is read.  Otherwise, the caller must free the buffer, using FreePool,
  when finished with it.

  @param[in]  DirHandle         The file handle of the directory to search.
  @param[out] FileInfo          The pointer to pointer to buffer for file's information.

  @retval EFI_SUCCESS           Found the first file.
  @retval EFI_NOT_FOUND         Cannot find the directory.
  @retval EFI_NO_MEDIA          The device has no media.
  @retval EFI_DEVICE_ERROR      The device reported an error.
  @retval EFI_VOLUME_CORRUPTED  The file system structures are corrupted.
  @return Others                status of FileHandleGetInfo, FileHandleSetPosition,
                                or FileHandleRead

**/
STATIC
EFI_STATUS
FileHandleFindFirstFile (
  IN EFI_FILE_HANDLE            DirHandle,
  OUT EFI_FILE_INFO             **FileInfo
  )
{
  EFI_STATUS     Status;
  UINTN          BufferSize;
  EFI_FILE_INFO  *TempFileInfo;

  TempFileInfo = NULL;

  //
  // Allocate a buffer sized to struct size + enough for the string at the end
  //
  BufferSize = MAX_FILE_INFO_LEN;
  TempFileInfo = AllocateZeroPool(BufferSize);
  if (TempFileInfo == NULL){
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Reset to the begining of the directory
  //
  Status = DirHandle->SetPosition(DirHandle, 0);
  if (EFI_ERROR(Status)) {
    FreePool(TempFileInfo);
    return Status;
  }

  //
  // Read in the info about the first file
  //
  Status = DirHandle->Read(DirHandle, &BufferSize, TempFileInfo);
  if (EFI_ERROR(Status)) {
    FreePool(TempFileInfo);
    return Status;
  }

  //
  // If we read 0 bytes (but did not have erros) we already read in the last file.
  //
  if (BufferSize == 0) {
    FreePool(TempFileInfo);
    return EFI_NOT_FOUND;
  }

  *FileInfo = TempFileInfo;

  return EFI_SUCCESS;
}


/** Retrieve next entries from a directory.

  To use this function, the caller must first call the FileHandleFindFirstFile()
  function to get the first directory entry.  Subsequent directory entries are
  retrieved by using the FileHandleFindNextFile() function.  This function can
  be called several times to get each entry from the directory.  If the call of
  FileHandleFindNextFile() retrieved the last directory entry, the next call of
  this function will set *NoFile to TRUE and free the buffer.

  @param[in]  DirHandle         The file handle of the directory.
  @param[out] Buffer            The pointer to buffer for file's information.
  @param[out] NoFile            The pointer to boolean when last file is found.

  @retval EFI_SUCCESS           Found the next file, or reached last file
  @retval EFI_NO_MEDIA          The device has no media.
  @retval EFI_DEVICE_ERROR      The device reported an error.
  @retval EFI_VOLUME_CORRUPTED  The file system structures are corrupted.

**/
STATIC
EFI_STATUS
FileHandleFindNextFile(
  IN EFI_FILE_HANDLE         DirHandle,
  OUT EFI_FILE_INFO          **FileInfo,
  OUT BOOLEAN                *NoFile
  )
{
  EFI_STATUS     Status;
  UINTN          BufferSize;
  EFI_FILE_INFO  *TempFileInfo;

  TempFileInfo = NULL;

  //
  // Allocate a buffer sized to struct size + enough for the string at the end
  //
  BufferSize = MAX_FILE_INFO_LEN;
  TempFileInfo = AllocateZeroPool(BufferSize);
  if (TempFileInfo == NULL){
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // This BufferSize MUST stay equal to the originally allocated one in FindFirstFile
  //
  BufferSize = MAX_FILE_INFO_LEN;

  //
  // Read in the info about the next file
  //
  Status = DirHandle->Read(DirHandle, &BufferSize, TempFileInfo);
  if (EFI_ERROR(Status)) {
    FreePool(TempFileInfo);
    return Status;
  }

  //
  // If we read 0 bytes (but did not have erros) we already read in the last file.
  //
  if (BufferSize != 0) {
    *FileInfo = TempFileInfo;
    *NoFile = FALSE;
  } else {
    FreePool(TempFileInfo);
    *NoFile = TRUE;
  }

  return EFI_SUCCESS;
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
  IN  LIST_ENTRY                      ActiveBootLists, OPTIONAL
  OUT EFI_SIMPLE_FILE_SYSTEM_PROTOCOL **Fs
  )
{
  EFI_STATUS                   Status;
  BDS_COMMON_OPTION            *BootOption;
  LIST_ENTRY                   DefaultBootLists;
  LIST_ENTRY                   BootLists;
  LIST_ENTRY                   *Link;
  EFI_DEVICE_PATH_PROTOCOL     *FilePath;
  EFI_DEVICE_PATH_PROTOCOL     *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL     *TempDevicePath;
  HARDDRIVE_DEVICE_PATH        *Hd;
  EFI_HANDLE                   ImageHandle;
  EFI_HANDLE                   Handle;

  *Fs              = NULL;
  ImageHandle      = NULL;
  TempDevicePath   = NULL;
  DefaultBootLists = NULL;

  if (ActiveBootLists == NULL) {
    Status = GetDefaultActiveBootOptionList(&DefaultBootLists);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    BootLists = DefaultBootLists;
  } else {
    BootLists = ActiveBootLists;
  }

  //
  // Search BootOptionList to check if it is an active boot option with EFI system partition
  //  1. Connect device path
  //  2. expend short/plug in devicepath
  //  3. LoadImage
  //
  for (Link = BootLists.ForwardLink; Link != &BootLists; Link = Link->ForwardLink) {
    //
    // Get the boot option from the link list
    //
    BootOption = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);
    DevicePath = BootOption->DevicePath;

    //
    // Skip LOAD_OPTION_ACTIVE boot option &  BBS device path
    //
    if (!IS_LOAD_OPTION_TYPE (BootOption->Attribute, LOAD_OPTION_ACTIVE) ||
        DevicePathType (DevicePath) == BBS_DEVICE_PATH)) {
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
    TempDevicePath = NULL;
    ImageHandle    = BdsExpandUsbShortFormDevicePath (DevicePath, &TempDevicePath);
    if (TempDevicePath != NULL) {
      DevicePath = TempDevicePath;
    }

    if(ImageHandle != NULL) {
      gBS->UnloadImage(ImageHandle);
    }

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
          break;
        }
      }
    }
  }

  //
  // No qualified EFI system partition found
  //
  if (*Fs == NULL) {
    Status = EFI_NOT_FOUND;
  }

  //
  // Free all BootOption entry on list
  //
  while(DefaultBootLists != NULL && !IsListEmpty(&DefaultBootLists)) {
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
GetFileInAlphabetFromDir(
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
    FileCount = 0;
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
      FreePool(TempFilePtrBuf[FileCount].ImageAddress);
      FreePool(FileInfo);
      TempFilePtrBuf[FileCount].ImageAddress = NULL;
      TempFilePtrBuf[FileCount].FileInfo     = NULL;
      //
      // Remove this error file info accordingly
      // & move Link to BackLink
      //
      Link = RemoveEntryList(Link);
      Link = Link->BackLink;
      FreePool(FileInfoEntry);
      continue;
    }
    TempFilePtrBuf[FileCount].FileInfo = FileInfo;
    FileCount++;
  }


EXIT:

  *FilePtr = TempFilePtrBuf;
  *FileNum = FileCount;

  while(!IsListEmpty(&FileInfoList)) {
    Link = FileInfoList.ForwardLink; 
    RemoveEntryList(Link);

    FileInfoEntry = CR (Link, FILE_INFO_ENTRY, Link, FILE_INFO_SIGNATURE);
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
    FileCount = 0;
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
    FileCount = 0;
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

/**

   This routine is called to get all caspules from file. The capsule file image is 
   copied to BS memory. Caller is responsible to free them.
  
  @param[out]   CapsulePtr           Copied Capsule file Image Info buffer
  @param[out]   CapsuleNum           CapsuleNumber

  @retval EFI_SUCCESS

**/
EFI_STATUS  
CodGetCapsuleFromFile(
  OUT IMAGE_INFO    **CapsulePtr,
  OUT UINTN         *CapsuleNum
  )
{
  EFI_STATUS                       Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_HANDLE                  RootDir;
  EFI_FILE_HANDLE                  FileDir;

  Fs      = NULL;
  RootDir = NULL;
  FileDir = NULL;

  Status = GetEfiSysPartitionFromActiveBootOption(&Fs);
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
    goto EXIT;
  }

  Status = GetFileInAlphabetFromDir(
             FileDir,
             EFI_FILE_READ_ONLY | EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE,
             CapsulePtr,
             CapsuleNum
             );

  RemoveFileFromDir(FileDir, EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE);

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
