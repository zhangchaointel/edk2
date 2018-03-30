/** @file
  Defines several datastructures used by Capsule On Disk feature

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _CAPSULES_H_
#define _CAPSULES_H_

//
// This data structure is the part of FILE_INFO_ENTRY
//
#define FILE_INFO_SIGNATURE SIGNATURE_32 ('F', 'L', 'I', 'F')

typedef struct {
  UINTN           Signature;
  LIST_ENTRY      Link;                  ///  Linked list members.
  EFI_FILE_INFO   *FileInfo;             ///  Pointer to the FileInfo struct for this file or NULL.
  CHAR16          *FnFirstPart;          ///  Text to the left of right-most period in the file name. String is capitialized
  CHAR16          *FnSecondPart;         ///  Text to the right of right-most period in the file name.String is capitialized. Maybe NULL
} FILE_INFO_ENTRY;

//
// (20 * (6+5+2))+1) unicode characters from EFI FAT spec (doubled for bytes)
//
#define MAX_FILE_NAME_SIZE   522
#define MAX_FILE_NAME_LEN    (MAX_FILE_NAME_SIZE / sizeof(CHAR16))

#define MAX_FILE_INFO_LEN    (OFFSET_OF(EFI_FILE_INFO, FileName) + MAX_FILE_NAME_LEN)

#endif // _CAPSULES_H_
