/** @file

  This library class defines a set of interfaces for processing Capsules from Disk.

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

BOOLEAN
CodLibCheckCapsuleOnDiskFlag(
  VOID
  );

/**

   This routine is called to get all caspules from file. The capsule file image is 
   copied to BS memory. Caller is responsible to free them.
  
  @param[out]   CapsulePtr           Copied Capsule file Image Info buffer
  @param[out]   CapsuleNum           CapsuleNumber

  @retval EFI_SUCCESS

**/
EFI_STATUS  
CodLibGetAllCapsuleOnDisk(
  OUT IMAGE_INFO    **CapsulePtr,
  OUT UINTN         *CapsuleNum
  );


/*
Reset OsIndication File Capsule Delivery Supported Flag
and clear the boot next variable.
*/
EFI_STATUS
CoDLibClearCapsuleOnDiskFlag(
  VOID
  );

#endif
