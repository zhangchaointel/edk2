/** @file
  Implement authentication services for the authenticated variables.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable data. It may be input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.
  Variable attribute should also be checked to avoid authentication bypass.
     The whole SMM authentication variable design relies on the integrity of flash part and SMM.
  which is assumed to be protected by platform.  All variable code and metadata in flash/SMM Memory
  may not be modified without authorization. If platform fails to protect these resources,
  the authentication service provided in this driver will be broken, and the behavior is undefined.

  ProcessVarWithPk(), ProcessVarWithKek() and ProcessVariable() are the function to do
  variable authentication.

  VerifyTimeBasedPayloadAndUpdate() and VerifyCounterBasedPayload() are sub function to do verification.
  They will do basic validation for authentication data structure, then call crypto library
  to verify the signature.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "AuthServiceInternal.h"

//
// Public Exponent of RSA Key.
//
CONST UINT8 mRsaE[] = { 0x01, 0x00, 0x01 };

CONST UINT8 mSha256OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

//
// Requirement for different signature type which have been defined in UEFI spec.
// These data are used to perform SignatureList format check while setting PK/KEK variable.
//
EFI_SIGNATURE_ITEM mSupportSigItem[] = {
//{SigType,                       SigHeaderSize,   SigDataSize  }
  {EFI_CERT_SHA256_GUID,          0,               32           },
  {EFI_CERT_RSA2048_GUID,         0,               256          },
  {EFI_CERT_RSA2048_SHA256_GUID,  0,               256          },
  {EFI_CERT_SHA1_GUID,            0,               20           },
  {EFI_CERT_RSA2048_SHA1_GUID,    0,               256          },
  {EFI_CERT_X509_GUID,            0,               ((UINT32) ~0)},
  {EFI_CERT_SHA224_GUID,          0,               28           },
  {EFI_CERT_SHA384_GUID,          0,               48           },
  {EFI_CERT_SHA512_GUID,          0,               64           },
  {EFI_CERT_X509_SHA256_GUID,     0,               48           },
  {EFI_CERT_X509_SHA384_GUID,     0,               64           },
  {EFI_CERT_X509_SHA512_GUID,     0,               80           }
};

BOOLEAN IsZeroNonce(
   IN  UINT8   *NonceData,   
   IN  UINTN   NonceDataSize
 )
{
  UINTN Index;

  for (Index = 0; Index < NonceDataSize; Index++) {
    if (NonceData[Index] != 0) {
      return FALSE;
    }
  }

  return TRUE;
}


/**
  Finds variable in storage blocks of volatile and non-volatile storage areas.

  This code finds variable in storage blocks of volatile and non-volatile storage areas.
  If VariableName is an empty string, then we just return the first
  qualified variable without comparing VariableName and VendorGuid.

  @param[in]  VariableName          Name of the variable to be found.
  @param[in]  VendorGuid            Variable vendor GUID to be found.
  @param[out] Data                  Pointer to data address.
  @param[out] DataSize              Pointer to data size.

  @retval EFI_INVALID_PARAMETER     If VariableName is not an empty string,
                                    while VendorGuid is NULL.
  @retval EFI_SUCCESS               Variable successfully found.
  @retval EFI_NOT_FOUND             Variable not found

**/
EFI_STATUS
AuthServiceInternalFindVariable (
  IN  CHAR16            *VariableName,
  IN  EFI_GUID          *VendorGuid,
  OUT VOID              **Data,
  OUT UINTN             *DataSize
  )
{
  EFI_STATUS            Status;
  AUTH_VARIABLE_INFO    AuthVariableInfo;

  ZeroMem (&AuthVariableInfo, sizeof (AuthVariableInfo));
  Status = mAuthVarLibContextIn->FindVariable (
           VariableName,
           VendorGuid,
           &AuthVariableInfo
           );
  *Data = AuthVariableInfo.Data;
  *DataSize = AuthVariableInfo.DataSize;
  return Status;
}

/**
  Update the variable region with Variable information.

  @param[in] VariableName           Name of variable.
  @param[in] VendorGuid             Guid of variable.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.

  @retval EFI_SUCCESS               The update operation is success.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
EFI_STATUS
AuthServiceInternalUpdateVariable (
  IN CHAR16             *VariableName,
  IN EFI_GUID           *VendorGuid,
  IN VOID               *Data,
  IN UINTN              DataSize,
  IN UINT32             Attributes
  )
{
  AUTH_VARIABLE_INFO    AuthVariableInfo;

  ZeroMem (&AuthVariableInfo, sizeof (AuthVariableInfo));
  AuthVariableInfo.VariableName = VariableName;
  AuthVariableInfo.VendorGuid = VendorGuid;
  AuthVariableInfo.Data = Data;
  AuthVariableInfo.DataSize = DataSize;
  AuthVariableInfo.Attributes = Attributes;

  return mAuthVarLibContextIn->UpdateVariable (
           &AuthVariableInfo
           );
}

/**
  Update the variable region with Variable information.

  @param[in] VariableName           Name of variable.
  @param[in] VendorGuid             Guid of variable.
  @param[in] Data                   Data pointer.
  @param[in] DataSize               Size of Data.
  @param[in] Attributes             Attribute value of the variable.
  @param[in] TimeStamp              Value of associated TimeStamp.

  @retval EFI_SUCCESS               The update operation is success.
  @retval EFI_INVALID_PARAMETER     Invalid parameter.
  @retval EFI_WRITE_PROTECTED       Variable is write-protected.
  @retval EFI_OUT_OF_RESOURCES      There is not enough resource.

**/
EFI_STATUS
AuthServiceInternalUpdateVariableWithTimeStamp (
  IN CHAR16             *VariableName,
  IN EFI_GUID           *VendorGuid,
  IN VOID               *Data,
  IN UINTN              DataSize,
  IN UINT32             Attributes,
  IN EFI_TIME           *TimeStamp
  )
{
  EFI_STATUS            FindStatus;
  VOID                  *OrgData;
  UINTN                 OrgDataSize;
  AUTH_VARIABLE_INFO    AuthVariableInfo;

  FindStatus = AuthServiceInternalFindVariable (
                 VariableName,
                 VendorGuid,
                 &OrgData,
                 &OrgDataSize
                 );

  //
  // EFI_VARIABLE_APPEND_WRITE attribute only effects for existing variable
  //
  if (!EFI_ERROR (FindStatus) && ((Attributes & EFI_VARIABLE_APPEND_WRITE) != 0)) {
    if ((CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
        ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE) == 0) || (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
        (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE2) == 0))) ||
        (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_KEY_EXCHANGE_KEY_NAME) == 0))) {
      //
      // For variables with formatted as EFI_SIGNATURE_LIST, the driver shall not perform an append of
      // EFI_SIGNATURE_DATA values that are already part of the existing variable value.
      //
      FilterSignatureList (
        OrgData,
        OrgDataSize,
        Data,
        &DataSize
        );
    }
  }

  ZeroMem (&AuthVariableInfo, sizeof (AuthVariableInfo));
  AuthVariableInfo.VariableName = VariableName;
  AuthVariableInfo.VendorGuid = VendorGuid;
  AuthVariableInfo.Data = Data;
  AuthVariableInfo.DataSize = DataSize;
  AuthVariableInfo.Attributes = Attributes;
  AuthVariableInfo.TimeStamp = TimeStamp;
  return mAuthVarLibContextIn->UpdateVariable (
           &AuthVariableInfo
           );
}

/**
  Determine whether this operation needs a physical present user.

  @param[in]      VariableName            Name of the Variable.
  @param[in]      VendorGuid              GUID of the Variable.

  @retval TRUE      This variable is protected, only a physical present user could set this variable.
  @retval FALSE     This variable is not protected.

**/
BOOLEAN
NeedPhysicallyPresent(
  IN     CHAR16         *VariableName,
  IN     EFI_GUID       *VendorGuid
  )
{
  if ((CompareGuid (VendorGuid, &gEfiSecureBootEnableDisableGuid) && (StrCmp (VariableName, EFI_SECURE_BOOT_ENABLE_NAME) == 0))
    || (CompareGuid (VendorGuid, &gEfiCustomModeEnableGuid) && (StrCmp (VariableName, EFI_CUSTOM_MODE_NAME) == 0))) {
    return TRUE;
  }

  return FALSE;
}

/**
  Determine whether the platform is operating in Custom Secure Boot mode.

  @retval TRUE           The platform is operating in Custom mode.
  @retval FALSE          The platform is operating in Standard mode.

**/
BOOLEAN
InCustomMode (
  VOID
  )
{
  EFI_STATUS    Status;
  VOID          *Data;
  UINTN         DataSize;

  Status = AuthServiceInternalFindVariable (EFI_CUSTOM_MODE_NAME, &gEfiCustomModeEnableGuid, &Data, &DataSize);
  if (!EFI_ERROR (Status) && (*(UINT8 *) Data == CUSTOM_SECURE_BOOT_MODE)) {
    return TRUE;
  }

  return FALSE;
}

/**
  Update platform mode.

  @param[in]      Mode                    SETUP_MODE or USER_MODE.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SUCCESS                     Update platform mode successfully.

**/
EFI_STATUS
UpdatePlatformMode (
  IN  UINT32                    Mode
  )
{
  EFI_STATUS              Status;
  VOID                    *Data;
  UINTN                   DataSize;
  UINT8                   SecureBootMode;
  UINT8                   SecureBootEnable;
  UINTN                   VariableDataSize;

  Status = AuthServiceInternalFindVariable (
             EFI_SETUP_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &Data,
             &DataSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Update the value of SetupMode variable by a simple mem copy, this could avoid possible
  // variable storage reclaim at runtime.
  //
  mPlatformMode = (UINT8) Mode;
  CopyMem (Data, &mPlatformMode, sizeof(UINT8));

  if (mAuthVarLibContextIn->AtRuntime ()) {
    //
    // SecureBoot Variable indicates whether the platform firmware is operating
    // in Secure boot mode (1) or not (0), so we should not change SecureBoot
    // Variable in runtime.
    //
    return Status;
  }

  //
  // Check "SecureBoot" variable's existence.
  // If it doesn't exist, firmware has no capability to perform driver signing verification,
  // then set "SecureBoot" to 0.
  //
  Status = AuthServiceInternalFindVariable (
             EFI_SECURE_BOOT_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &Data,
             &DataSize
             );
  //
  // If "SecureBoot" variable exists, then check "SetupMode" variable update.
  // If "SetupMode" variable is USER_MODE, "SecureBoot" variable is set to 1.
  // If "SetupMode" variable is SETUP_MODE, "SecureBoot" variable is set to 0.
  //
  if (EFI_ERROR (Status)) {
    SecureBootMode = SECURE_BOOT_MODE_DISABLE;
  } else {
    if (mPlatformMode == USER_MODE) {
      SecureBootMode = SECURE_BOOT_MODE_ENABLE;
    } else if (mPlatformMode == SETUP_MODE) {
      SecureBootMode = SECURE_BOOT_MODE_DISABLE;
    } else {
      return EFI_NOT_FOUND;
    }
  }

  Status  = AuthServiceInternalUpdateVariable (
              EFI_SECURE_BOOT_MODE_NAME,
              &gEfiGlobalVariableGuid,
              &SecureBootMode,
              sizeof(UINT8),
              EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS
              );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Check "SecureBootEnable" variable's existence. It can enable/disable secure boot feature.
  //
  Status = AuthServiceInternalFindVariable (
             EFI_SECURE_BOOT_ENABLE_NAME,
             &gEfiSecureBootEnableDisableGuid,
             &Data,
             &DataSize
             );

  if (SecureBootMode == SECURE_BOOT_MODE_ENABLE) {
    //
    // Create the "SecureBootEnable" variable as secure boot is enabled.
    //
    SecureBootEnable = SECURE_BOOT_ENABLE;
    VariableDataSize = sizeof (SecureBootEnable);
  } else {
    //
    // Delete the "SecureBootEnable" variable if this variable exist as "SecureBoot"
    // variable is not in secure boot state.
    //
    if (EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }
    SecureBootEnable = SECURE_BOOT_DISABLE;
    VariableDataSize = 0;
  }

  Status = AuthServiceInternalUpdateVariable (
             EFI_SECURE_BOOT_ENABLE_NAME,
             &gEfiSecureBootEnableDisableGuid,
             &SecureBootEnable,
             VariableDataSize,
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS
             );
  return Status;
}

/**
  Check input data form to make sure it is a valid EFI_SIGNATURE_LIST for PK/KEK/db/dbx/dbt variable.

  @param[in]  VariableName                Name of Variable to be check.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Point to the variable data to be checked.
  @param[in]  DataSize                    Size of Data.

  @return EFI_INVALID_PARAMETER           Invalid signature list format.
  @return EFI_SUCCESS                     Passed signature list format check successfully.

**/
EFI_STATUS
CheckSignatureListFormat(
  IN  CHAR16                    *VariableName,
  IN  EFI_GUID                  *VendorGuid,
  IN  VOID                      *Data,
  IN  UINTN                     DataSize
  )
{
  EFI_SIGNATURE_LIST     *SigList;
  UINTN                  SigDataSize;
  UINT32                 Index;
  UINT32                 SigCount;
  BOOLEAN                IsPk;
  VOID                   *RsaContext;
  EFI_SIGNATURE_DATA     *CertData;
  UINTN                  CertLen;

  if (DataSize == 0) {
    return EFI_SUCCESS;
  }

  ASSERT (VariableName != NULL && VendorGuid != NULL && Data != NULL);

  if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_PLATFORM_KEY_NAME) == 0)){
    IsPk = TRUE;
  } else if ((CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) ||
             (CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
             ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE) == 0) || (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
              (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE2) == 0)))) {
    IsPk = FALSE;
  } else {
    return EFI_SUCCESS;
  }

  SigCount = 0;
  SigList  = (EFI_SIGNATURE_LIST *) Data;
  SigDataSize  = DataSize;
  RsaContext = NULL;

  //
  // Walk throuth the input signature list and check the data format.
  // If any signature is incorrectly formed, the whole check will fail.
  //
  while ((SigDataSize > 0) && (SigDataSize >= SigList->SignatureListSize)) {
    for (Index = 0; Index < (sizeof (mSupportSigItem) / sizeof (EFI_SIGNATURE_ITEM)); Index++ ) {
      if (CompareGuid (&SigList->SignatureType, &mSupportSigItem[Index].SigType)) {
        //
        // The value of SignatureSize should always be 16 (size of SignatureOwner
        // component) add the data length according to signature type.
        //
        if (mSupportSigItem[Index].SigDataSize != ((UINT32) ~0) &&
          (SigList->SignatureSize - sizeof (EFI_GUID)) != mSupportSigItem[Index].SigDataSize) {
          return EFI_INVALID_PARAMETER;
        }
        if (mSupportSigItem[Index].SigHeaderSize != ((UINT32) ~0) &&
          SigList->SignatureHeaderSize != mSupportSigItem[Index].SigHeaderSize) {
          return EFI_INVALID_PARAMETER;
        }
        break;
      }
    }

    if (Index == (sizeof (mSupportSigItem) / sizeof (EFI_SIGNATURE_ITEM))) {
      //
      // Undefined signature type.
      //
      return EFI_INVALID_PARAMETER;
    }

    if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Guid)) {
      //
      // Try to retrieve the RSA public key from the X.509 certificate.
      // If this operation fails, it's not a valid certificate.
      //
      RsaContext = RsaNew ();
      if (RsaContext == NULL) {
        return EFI_INVALID_PARAMETER;
      }
      CertData = (EFI_SIGNATURE_DATA *) ((UINT8 *) SigList + sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize);
      CertLen = SigList->SignatureSize - sizeof (EFI_GUID);
      if (!RsaGetPublicKeyFromX509 (CertData->SignatureData, CertLen, &RsaContext)) {
        RsaFree (RsaContext);
        return EFI_INVALID_PARAMETER;
      }
      RsaFree (RsaContext);
    }

    if ((SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) % SigList->SignatureSize != 0) {
      return EFI_INVALID_PARAMETER;
    }
    SigCount += (SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) / SigList->SignatureSize;

    SigDataSize -= SigList->SignatureListSize;
    SigList = (EFI_SIGNATURE_LIST *) ((UINT8 *) SigList + SigList->SignatureListSize);
  }

  if (((UINTN) SigList - (UINTN) Data) != DataSize) {
    return EFI_INVALID_PARAMETER;
  }

  if (IsPk && SigCount > 1) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

/**
  Update "VendorKeys" variable to record the out of band secure boot key modification.

  @return EFI_SUCCESS           Variable is updated successfully.
  @return Others                Failed to update variable.

**/
EFI_STATUS
VendorKeyIsModified (
  VOID
  )
{
  EFI_STATUS              Status;

  if (mVendorKeyState == VENDOR_KEYS_MODIFIED) {
    return EFI_SUCCESS;
  }
  mVendorKeyState = VENDOR_KEYS_MODIFIED;

  Status = AuthServiceInternalUpdateVariable (
             EFI_VENDOR_KEYS_NV_VARIABLE_NAME,
             &gEfiVendorKeysNvGuid,
             &mVendorKeyState,
             sizeof (UINT8),
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return AuthServiceInternalUpdateVariable (
           EFI_VENDOR_KEYS_VARIABLE_NAME,
           &gEfiGlobalVariableGuid,
           &mVendorKeyState,
           sizeof (UINT8),
           EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS
           );
}

/**
  Process variable with platform key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable
  @param[in]  IsPk                        Indicate whether it is to process pk.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation.
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable passed validation successfully.

**/
EFI_STATUS
ProcessVarWithPk (
  IN  CHAR16                    *VariableName,
  IN  EFI_GUID                  *VendorGuid,
  IN  VOID                      *Data,
  IN  UINTN                     DataSize,
  IN  UINT32                    Attributes OPTIONAL,
  IN  BOOLEAN                   IsPk
  )
{
  EFI_STATUS                  Status;
  BOOLEAN                     Del;
  UINT8                       *Payload;
  UINTN                       PayloadSize;

  if ((Attributes & EFI_VARIABLE_NON_VOLATILE) == 0 ||
      (Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
    //
    // PK, KEK and db/dbx/dbt should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
    // authenticated variable.
    //
    return EFI_INVALID_PARAMETER;
  }

  //
  // Init state of Del. State may change due to secure check
  //
  Del = FALSE;
  if ((InCustomMode() && UserPhysicalPresent()) || (mPlatformMode == SETUP_MODE && !IsPk)) {
    Payload = (UINT8 *) Data + AUTHINFO2_SIZE (Data);
    PayloadSize = DataSize - AUTHINFO2_SIZE (Data);
    if (PayloadSize == 0) {
      Del = TRUE;
    }

    Status = CheckSignatureListFormat(VariableName, VendorGuid, Payload, PayloadSize);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = AuthServiceInternalUpdateVariableWithTimeStamp (
               VariableName,
               VendorGuid,
               Payload,
               PayloadSize,
               Attributes,
               &((EFI_VARIABLE_AUTHENTICATION_2 *) Data)->TimeStamp
               );
    if (EFI_ERROR(Status)) {
      return Status;
    }

    if ((mPlatformMode != SETUP_MODE) || IsPk) {
      Status = VendorKeyIsModified ();
    }
  } else if (mPlatformMode == USER_MODE) {
    //
    // Verify against X509 Cert in PK database.
    //
    Status = VerifyTimeBasedPayloadAndUpdate (
               VariableName,
               VendorGuid,
               Data,
               DataSize,
               Attributes,
               AuthVarTypePk,
               &Del
               );
  } else {
    //
    // Verify against the certificate in data payload.
    //
    Status = VerifyTimeBasedPayloadAndUpdate (
               VariableName,
               VendorGuid,
               Data,
               DataSize,
               Attributes,
               AuthVarTypePayload,
               &Del
               );
  }

  if (!EFI_ERROR(Status) && IsPk) {
    if (mPlatformMode == SETUP_MODE && !Del) {
      //
      // If enroll PK in setup mode, need change to user mode.
      //
      Status = UpdatePlatformMode (USER_MODE);
    } else if (mPlatformMode == USER_MODE && Del){
      //
      // If delete PK in user mode, need change to setup mode.
      //
      Status = UpdatePlatformMode (SETUP_MODE);
    }
  }

  return Status;
}

/**
  Process variable with key exchange key for verification.

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
ProcessVarWithKek (
  IN  CHAR16                               *VariableName,
  IN  EFI_GUID                             *VendorGuid,
  IN  VOID                                 *Data,
  IN  UINTN                                DataSize,
  IN  UINT32                               Attributes OPTIONAL
  )
{
  EFI_STATUS                      Status;
  UINT8                           *Payload;
  UINTN                           PayloadSize;

  if ((Attributes & EFI_VARIABLE_NON_VOLATILE) == 0 ||
      (Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) == 0) {
    //
    // DB, DBX and DBT should set EFI_VARIABLE_NON_VOLATILE attribute and should be a time-based
    // authenticated variable.
    //
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_SUCCESS;
  if (mPlatformMode == USER_MODE && !(InCustomMode() && UserPhysicalPresent())) {
    //
    // Time-based, verify against X509 Cert KEK.
    //
    return VerifyTimeBasedPayloadAndUpdate (
             VariableName,
             VendorGuid,
             Data,
             DataSize,
             Attributes,
             AuthVarTypeKek,
             NULL
             );
  } else {
    //
    // If in setup mode or custom secure boot mode, no authentication needed.
    //
    Payload = (UINT8 *) Data + AUTHINFO2_SIZE (Data);
    PayloadSize = DataSize - AUTHINFO2_SIZE (Data);

    Status = CheckSignatureListFormat(VariableName, VendorGuid, Payload, PayloadSize);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = AuthServiceInternalUpdateVariableWithTimeStamp (
               VariableName,
               VendorGuid,
               Payload,
               PayloadSize,
               Attributes,
               &((EFI_VARIABLE_AUTHENTICATION_2 *) Data)->TimeStamp
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (mPlatformMode != SETUP_MODE) {
      Status = VendorKeyIsModified ();
    }
  }

  return Status;
}

/**
  Check if it is to delete auth variable.

  @param[in] OrgAttributes      Original attribute value of the variable.
  @param[in] Data               Data pointer.
  @param[in] DataSize           Size of Data.
  @param[in] Attributes         Attribute value of the variable.

  @retval TRUE                  It is to delete auth variable.
  @retval FALSE                 It is not to delete auth variable.

**/
BOOLEAN
IsDeleteAuthVariable (
  IN  UINT32                    OrgAttributes,
  IN  VOID                      *Data,
  IN  UINTN                     DataSize,
  IN  UINT32                    Attributes
  )
{
  BOOLEAN                       Del;
  UINTN                         PayloadSize;

  Del = FALSE;

  //
  // To delete a variable created with the EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
  // or the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute,
  // SetVariable must be used with attributes matching the existing variable
  // and the DataSize set to the size of the AuthInfo descriptor.
  //
  if ((Attributes == OrgAttributes) &&
      ((Attributes & (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS)) != 0)) {
    if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
      PayloadSize = DataSize - AUTHINFO2_SIZE (Data);
      if (PayloadSize == 0) {
        Del = TRUE;
      }
    } else if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
      //
      // No payload attached and no NewCert descriptor
      //
      if (DataSize == ((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->MetadataSize && 
          ((((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) == 0)) {
        Del = TRUE;
      }
    } else {
      PayloadSize = DataSize - AUTHINFO_SIZE;
      if (PayloadSize == 0) {
        Del = TRUE;
      }
    }
  }

  return Del;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.
  This function will check attribute carefully to avoid authentication bypass.

  @param[in]  VariableName                Name of the variable.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data.
  @param[in]  Attributes                  Attribute value of the variable.

  @return EFI_INVALID_PARAMETER           Invalid parameter.
  @return EFI_WRITE_PROTECTED             Variable is write-protected and needs authentication with
                                          EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set.
  @return EFI_OUT_OF_RESOURCES            The Database to save the public key is full.
  @return EFI_SECURITY_VIOLATION          The variable is with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                                          set, but the AuthInfo does NOT pass the validation
                                          check carried out by the firmware.
  @return EFI_SUCCESS                     Variable is not write-protected or pass validation successfully.

**/
EFI_STATUS
ProcessVariable (
  IN     CHAR16                             *VariableName,
  IN     EFI_GUID                           *VendorGuid,
  IN     VOID                               *Data,
  IN     UINTN                              DataSize,
  IN     UINT32                             Attributes
  )
{
  EFI_STATUS                      Status;
  AUTH_VARIABLE_INFO              OrgVariableInfo;

  Status      = EFI_SUCCESS;

  ZeroMem (&OrgVariableInfo, sizeof (OrgVariableInfo));
  Status = mAuthVarLibContextIn->FindVariable (
             VariableName,
             VendorGuid,
             &OrgVariableInfo
             );

  if ((!EFI_ERROR (Status)) && IsDeleteAuthVariable (OrgVariableInfo.Attributes, Data, DataSize, Attributes) && UserPhysicalPresent()) {
    //
    // Allow the delete operation of common authenticated variable(AT, EA or AW) at user physical presence.
    //
    Status = AuthServiceInternalUpdateVariable (
              VariableName,
              VendorGuid,
              NULL,
              0,
              0
              );
    if (!EFI_ERROR (Status) && 
        ((Attributes & (EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS)) != 0)) {
      Status = DeleteCertsFromDb (VariableName, VendorGuid, Attributes);
    }
    return Status;
  }

  if (NeedPhysicallyPresent (VariableName, VendorGuid) && !UserPhysicalPresent()) {
    //
    // This variable is protected, only physical present user could modify its value.
    //
    return EFI_SECURITY_VIOLATION;
  }

  //
  if ((Attributes & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) {
    //
    // Reject Counter Based Auth Variable processing request.
    //
    return EFI_UNSUPPORTED;
  } else if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
    //
    // Process Time-based Authenticated variable.
    //
    return VerifyTimeBasedPayloadAndUpdate (
             VariableName,
             VendorGuid,
             Data,
             DataSize,
             Attributes,
             AuthVarTypePriv,
             NULL
             );
  } else if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
    //
    // Process Enhanced Authenticated variable.
    //
    return VerifyEnhancedAuthPayloadAndUpdate (
             VariableName,
             VendorGuid,
             Data,
             DataSize,
             Attributes
             );
  }

  if ((OrgVariableInfo.Data != NULL) &&
     ((OrgVariableInfo.Attributes & VARIABLE_ATTRIBUTE_AT_EA_AW) != 0)) {
    //
    // If the variable is already write-protected, it always needs authentication before update.
    //
    return EFI_WRITE_PROTECTED;
  }

  //
  // Not authenticated variable, just update variable as usual.
  //
  Status = AuthServiceInternalUpdateVariable (VariableName, VendorGuid, Data, DataSize, Attributes);
  return Status;

}

/**
  Filter out the duplicated EFI_SIGNATURE_DATA from the new data by comparing to the original data.

  @param[in]        Data          Pointer to original EFI_SIGNATURE_LIST.
  @param[in]        DataSize      Size of Data buffer.
  @param[in, out]   NewData       Pointer to new EFI_SIGNATURE_LIST.
  @param[in, out]   NewDataSize   Size of NewData buffer.

**/
EFI_STATUS
FilterSignatureList (
  IN     VOID       *Data,
  IN     UINTN      DataSize,
  IN OUT VOID       *NewData,
  IN OUT UINTN      *NewDataSize
  )
{
  EFI_SIGNATURE_LIST    *CertList;
  EFI_SIGNATURE_DATA    *Cert;
  UINTN                 CertCount;
  EFI_SIGNATURE_LIST    *NewCertList;
  EFI_SIGNATURE_DATA    *NewCert;
  UINTN                 NewCertCount;
  UINTN                 Index;
  UINTN                 Index2;
  UINTN                 Size;
  UINT8                 *Tail;
  UINTN                 CopiedCount;
  UINTN                 SignatureListSize;
  BOOLEAN               IsNewCert;
  UINT8                 *TempData;
  UINTN                 TempDataSize;
  EFI_STATUS            Status;

  if (*NewDataSize == 0) {
    return EFI_SUCCESS;
  }

  TempDataSize = *NewDataSize;
  Status = mAuthVarLibContextIn->GetScratchBuffer (&TempDataSize, (VOID **) &TempData);
  if (EFI_ERROR (Status)) {
    return EFI_OUT_OF_RESOURCES;
  }

  Tail = TempData;

  NewCertList = (EFI_SIGNATURE_LIST *) NewData;
  while ((*NewDataSize > 0) && (*NewDataSize >= NewCertList->SignatureListSize)) {
    NewCert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) NewCertList + sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize);
    NewCertCount = (NewCertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - NewCertList->SignatureHeaderSize) / NewCertList->SignatureSize;

    CopiedCount = 0;
    for (Index = 0; Index < NewCertCount; Index++) {
      IsNewCert = TRUE;

      Size = DataSize;
      CertList = (EFI_SIGNATURE_LIST *) Data;
      while ((Size > 0) && (Size >= CertList->SignatureListSize)) {
        if (CompareGuid (&CertList->SignatureType, &NewCertList->SignatureType) &&
           (CertList->SignatureSize == NewCertList->SignatureSize)) {
          Cert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
          CertCount = (CertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
          for (Index2 = 0; Index2 < CertCount; Index2++) {
            //
            // Iterate each Signature Data in this Signature List.
            //
            if (CompareMem (NewCert, Cert, CertList->SignatureSize) == 0) {
              IsNewCert = FALSE;
              break;
            }
            Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
          }
        }

        if (!IsNewCert) {
          break;
        }
        Size -= CertList->SignatureListSize;
        CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
      }

      if (IsNewCert) {
        //
        // New EFI_SIGNATURE_DATA, keep it.
        //
        if (CopiedCount == 0) {
          //
          // Copy EFI_SIGNATURE_LIST header for only once.
          //
          CopyMem (Tail, NewCertList, sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize);
          Tail = Tail + sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize;
        }

        CopyMem (Tail, NewCert, NewCertList->SignatureSize);
        Tail += NewCertList->SignatureSize;
        CopiedCount++;
      }

      NewCert = (EFI_SIGNATURE_DATA *) ((UINT8 *) NewCert + NewCertList->SignatureSize);
    }

    //
    // Update SignatureListSize in the kept EFI_SIGNATURE_LIST.
    //
    if (CopiedCount != 0) {
      SignatureListSize = sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize + (CopiedCount * NewCertList->SignatureSize);
      CertList = (EFI_SIGNATURE_LIST *) (Tail - SignatureListSize);
      CertList->SignatureListSize = (UINT32) SignatureListSize;
    }

    *NewDataSize -= NewCertList->SignatureListSize;
    NewCertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) NewCertList + NewCertList->SignatureListSize);
  }

  TempDataSize = (Tail - (UINT8 *) TempData);

  CopyMem (NewData, TempData, TempDataSize);
  *NewDataSize = TempDataSize;

  return EFI_SUCCESS;
}

/**
  Compare two EFI_TIME data.


  @param FirstTime           A pointer to the first EFI_TIME data.
  @param SecondTime          A pointer to the second EFI_TIME data.

  @retval  TRUE              The FirstTime is not later than the SecondTime.
  @retval  FALSE             The FirstTime is later than the SecondTime.

**/
BOOLEAN
AuthServiceInternalCompareTimeStamp (
  IN EFI_TIME               *FirstTime,
  IN EFI_TIME               *SecondTime
  )
{
  if (FirstTime->Year != SecondTime->Year) {
    return (BOOLEAN) (FirstTime->Year < SecondTime->Year);
  } else if (FirstTime->Month != SecondTime->Month) {
    return (BOOLEAN) (FirstTime->Month < SecondTime->Month);
  } else if (FirstTime->Day != SecondTime->Day) {
    return (BOOLEAN) (FirstTime->Day < SecondTime->Day);
  } else if (FirstTime->Hour != SecondTime->Hour) {
    return (BOOLEAN) (FirstTime->Hour < SecondTime->Hour);
  } else if (FirstTime->Minute != SecondTime->Minute) {
    return (BOOLEAN) (FirstTime->Minute < SecondTime->Minute);
  }

  return (BOOLEAN) (FirstTime->Second <= SecondTime->Second);
}

/**
  Calculate SHA256 digest of SignerCert CommonName + ToplevelCert tbsCertificate
  SignerCert and ToplevelCert are inside the signer certificate chain.

  @param[in]  SignerCert          A pointer to SignerCert data.
  @param[in]  SignerCertSize      Length of SignerCert data.
  @param[in]  TopLevelCert        A pointer to TopLevelCert data.
  @param[in]  TopLevelCertSize    Length of TopLevelCert data.
  @param[out] Sha256Digest       Sha256 digest calculated.

  @return EFI_ABORTED          Digest process failed.
  @return EFI_SUCCESS          SHA256 Digest is succesfully calculated.

**/
EFI_STATUS
CalculatePrivAuthVarSignChainSHA256Digest(
  IN     UINT8            *SignerCert,
  IN     UINTN            SignerCertSize,
  IN     UINT8            *TopLevelCert,
  IN     UINTN            TopLevelCertSize,
  OUT    UINT8            *Sha256Digest
  )
{
  UINT8                   *TbsCert;
  UINTN                   TbsCertSize;
  CHAR8                   CertCommonName[128];
  UINTN                   CertCommonNameSize;
  BOOLEAN                 CryptoStatus;
  EFI_STATUS              Status;

  CertCommonNameSize = sizeof(CertCommonName);

  //
  // Get SignerCert CommonName
  //
  Status = X509GetCommonName(SignerCert, SignerCertSize, CertCommonName, &CertCommonNameSize);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "%a Get SignerCert CommonName failed with status %x\n", __FUNCTION__, Status));
    return EFI_ABORTED;
  }

  //
  // Get TopLevelCert tbsCertificate
  //
  if (!X509GetTBSCert(TopLevelCert, TopLevelCertSize, &TbsCert, &TbsCertSize)) {
    DEBUG((DEBUG_INFO, "%a Get Top-level Cert tbsCertificate failed!\n", __FUNCTION__));
    return EFI_ABORTED;
  }

  //
  // Digest SignerCert CN + TopLevelCert tbsCertificate
  //
  ZeroMem (Sha256Digest, SHA256_DIGEST_SIZE);
  CryptoStatus = Sha256Init (mHashCtx);
  if (!CryptoStatus) {
    return EFI_ABORTED;
  }

  //
  // '\0' is forced in CertCommonName. No overflow issue
  //
  CryptoStatus = Sha256Update (
                   mHashCtx,
                   CertCommonName,
                   AsciiStrLen (CertCommonName)
                   );
  if (!CryptoStatus) {
    return EFI_ABORTED;
  }

  CryptoStatus = Sha256Update (mHashCtx, TbsCert, TbsCertSize);
  if (!CryptoStatus) {
    return EFI_ABORTED;
  }

  CryptoStatus  = Sha256Final (mHashCtx, Sha256Digest);
  if (!CryptoStatus) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}


/**
  Find matching signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb" or "certdbv".

  The data format of "certdb" or "certdbv":
  //
  //     UINT32 CertDbListSize;
  // /// AUTH_CERT_DB_DATA Certs1[];
  // /// AUTH_CERT_DB_DATA Certs2[];
  // /// ...
  // /// AUTH_CERT_DB_DATA Certsn[];
  //

 The data format of "encertdb" or "encertdbv":
  //
  //     UINT32 CertDbListSize;
  // /// ENHANCED_AUTH_CERT_DB_DATA Certs1[];
  // /// ENHANCED_AUTH_CERT_DB_DATA Certs2[];
  // /// ...
  // /// ENHANCED_AUTH_CERT_DB_DATA Certsn[];
  //

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Data           Pointer to variable "certdb" or "certdbv".
  @param[in]  DataSize       Size of variable "certdb" or "certdbv".
  @param[out] CertOffset     Offset of matching CertData, from starting of Data.
  @param[out] CertDataSize   Length of CertData in bytes.
  @param[out] CertNodeOffset Offset of matching AUTH_CERT_DB_DATA , from
                             starting of Data.
  @param[out] CertNodeSize   Length of AUTH_CERT_DB_DATA in bytes.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find matching certs.
  @retval  EFI_SUCCESS           Find matching certs and output parameters.

**/
EFI_STATUS
FindCertsFromDb (
  IN     CHAR16                              *VariableName,
  IN     EFI_GUID                            *VendorGuid,
  IN     UINT32                              Attributes,
  IN     UINT8                               *Data,
  IN     UINTN                               DataSize,
  OUT    UINT32                              *CertOffset,     OPTIONAL
  OUT    UINT32                              *CertDataSize,   OPTIONAL
  OUT    UINT32                              *CertNodeOffset, OPTIONAL
  OUT    UINT32                              *CertNodeSize,   OPTIONAL
  OUT    UINT32                              *NonceDataOffset,OPTIONAL
  OUT    UINT32                              *NonceDataSize,  OPTIONAL
  OUT    UINT8                               *Type            OPTIONAL
  )
{
  UINT8               *Ptr;
  UINT8               *DataTailPtr;
  UINT32              CertSize;
  UINT32              NameSize;
  UINT32              NodeSize;
  UINT32              CertDbListSize;
  UINT32              NonceSize;
  UINT8               TypeTemp;

  if ((VariableName == NULL) || (VendorGuid == NULL) || (Data == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check whether DataSize matches recorded CertDbListSize.
  //
  if (DataSize < sizeof (UINT32)) {
    return EFI_INVALID_PARAMETER;
  }

  CertDbListSize = ReadUnaligned32 ((UINT32 *) Data);

  if (CertDbListSize != (UINT32) DataSize) {
    return EFI_INVALID_PARAMETER;
  }

  Ptr         = Data + sizeof (UINT32);
  DataTailPtr = Data + DataSize;

  //
  // Get corresponding certificates by VendorGuid and VariableName.
  //
  while (Ptr < DataTailPtr) {
    //
    // Check whether VendorGuid matches.
    //
    if (CompareGuid (&((AUTH_CERT_DB_DATA *)Ptr)->VendorGuid, VendorGuid)) {
      NodeSize  = ReadUnaligned32 (&((AUTH_CERT_DB_DATA *)Ptr)->CertNodeSize);
      NameSize  = ReadUnaligned32 (&((AUTH_CERT_DB_DATA *)Ptr)->NameSize);
      CertSize  = ReadUnaligned32 (&((AUTH_CERT_DB_DATA *)Ptr)->CertDataSize);
      NonceSize = 0;
      TypeTemp  = 0;

      if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
        TypeTemp = *(Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertSize));
        ASSERT((TypeTemp == EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE) || (TypeTemp == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE));

        if (TypeTemp == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE) {
          NonceSize = ReadUnaligned32((UINT32 *)(Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertSize) + sizeof(UINT8)));
          ASSERT(NonceSize != 0);
        }

        //
        //   ENAHNCED_AUTH_CERT_DBD_DATA {
        //       AUTH_CERT_DB_DATA                                  CertData;
        //       UINT8                                                          Type;
        //       EFI_VARIABLE_AUTHENTICATION_3_NONCE   Nonce;
        //   }
        //
        if (NodeSize != SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertSize) + sizeof(UINT8) + sizeof(UINT32) + NonceSize) {
          return EFI_INVALID_PARAMETER;
        }
      } else if (NodeSize != SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertSize)) {
        return EFI_INVALID_PARAMETER;
      }

      //
      // Check whether VariableName matches.
      //
      if ((NameSize == StrLen (VariableName)) &&
          (CompareMem (Ptr + sizeof(AUTH_CERT_DB_DATA), VariableName, NameSize * sizeof (CHAR16)) == 0)) {

        if (CertOffset != NULL) {
          *CertOffset = (UINT32)(Ptr - Data) + sizeof(AUTH_CERT_DB_DATA) + NameSize * sizeof (CHAR16);
        }

        if (CertDataSize != NULL) {
          *CertDataSize = CertSize;
        }

        if (CertNodeOffset != NULL) {
          *CertNodeOffset = (UINT32) (Ptr - Data);
        }

        if (CertNodeSize != NULL) {
          *CertNodeSize = NodeSize;
        }

        if (NonceDataOffset != NULL) {
          *NonceDataOffset = (UINT32)(Ptr - Data) + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertSize) + sizeof(UINT8) + sizeof(UINT32);
        }

        if (NonceDataSize != NULL) {
          *NonceDataSize = NonceSize;
        }

        if (Type != NULL) {
          *Type = TypeTemp;
        }

        return EFI_SUCCESS;
      }
    } 

    NodeSize = ReadUnaligned32 (&((AUTH_CERT_DB_DATA *)Ptr)->CertNodeSize);
    Ptr     += NodeSize;

  }

  return EFI_NOT_FOUND;
}

EFI_STATUS 
GetCertDatabaseName(
  IN     UINT32      Attributes,
  OUT    CHAR16      **DatabaseName
  )
{
  CHAR16   *DbName;

  if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
    if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
      //
      // Get variable "certdb"
      //
      DbName = EFI_CERT_DB_NAME;
    } else {
      //
      // Get variable "certdbv"
      //
      DbName = EFI_CERT_DB_VOLATILE_NAME;
    }
  } else if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
    if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
      //
      // Get variable "encertdb"
      //
      DbName = EFI_ENHANCED_AUTH_CERT_DB_NAME;
    } else {
      //
      // Get variable "encertdbv"
      //
      DbName = EFI_ENHANCED_AUTH_CERT_DB_VOLATILE_NAME;
    }
  } else {
    return EFI_INVALID_PARAMETER;
  }

  *DatabaseName = DbName;

  return EFI_SUCCESS;
}

/**
  Retrieve signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb"
  or "certdbv" according to authenticated variable attributes.

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.
  @param[out] CertData       Pointer to signer's certificates.
  @param[out] CertDataSize   Length of CertData in bytes.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find "certdb"/"certdbv" or matching certs.
  @retval  EFI_SUCCESS           Get signer's certificates successfully.

**/
EFI_STATUS
GetCertsFromDb (
  IN     CHAR16           *VariableName,
  IN     EFI_GUID         *VendorGuid,
  IN     UINT32           Attributes,
  OUT    UINT8            **CertData,
  OUT    UINT32           *CertDataSize,
  OUT    UINT8            **NonceData,    OPTIONAL
  OUT    UINT32           *NonceDataSize, OPTIONAL
  OUT    UINT8            *Type
  )
{
  CHAR16                  *DbName;
  EFI_STATUS              Status;
  UINT8                   *Data;
  UINTN                   DataSize;
  UINT32                  CertOffset;
  UINT32                  NonceOffset;
  UINT32                  TempNonceDataSize;

  if ((VariableName == NULL) || (VendorGuid == NULL) || (CertData == NULL) || (CertDataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get Cert Database name by variable attributes
  //
  Status = GetCertDatabaseName(Attributes, &DbName);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // Get Cert Database content from variable
  //
  Status = AuthServiceInternalFindVariable (
             DbName,
             &gEfiCertDbGuid,
             (VOID **) &Data,
             &DataSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((DataSize == 0) || (Data == NULL)) {
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  Status = FindCertsFromDb (
             VariableName,
             VendorGuid,
             Attributes,
             Data,
             DataSize,
             &CertOffset,
             CertDataSize,
             NULL,
             NULL,
             &NonceOffset,
             &TempNonceDataSize,
             Type
             );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  *CertData = Data + CertOffset;

  if (NonceDataSize != NULL) {
    *NonceDataSize = TempNonceDataSize;
  }

  if (NonceData != NULL) {
    if (TempNonceDataSize != 0) {
      *NonceData = Data + NonceOffset;
    } else {
      //
      // NonceSize is zero
      //
      *NonceData = NULL;
    }
  }

  return EFI_SUCCESS;
}

/**
  Delete matching signer's certificates when deleting common authenticated
  variable by corresponding VariableName and VendorGuid from "certdb" or 
  "certdbv" according to authenticated variable attributes.

  @param[in]  VariableName   Name of authenticated Variable.
  @param[in]  VendorGuid     Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_NOT_FOUND         Fail to find "certdb"/"certdbv" or matching certs.
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           The operation is completed successfully.

**/
EFI_STATUS
DeleteCertsFromDb (
  IN     CHAR16           *VariableName,
  IN     EFI_GUID         *VendorGuid,
  IN     UINT32           Attributes
  )
{
  EFI_STATUS              Status;
  UINT8                   *Data;
  UINTN                   DataSize;
  UINT32                  VarAttr;
  UINT32                  CertNodeOffset;
  UINT32                  CertNodeSize;
  UINT8                   *NewCertDb;
  UINT32                  NewCertDbSize;
  CHAR16                  *DbName;

  if ((VariableName == NULL) || (VendorGuid == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get Cert Database name by variable attributes
  //
  Status = GetCertDatabaseName(Attributes, &DbName);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
    VarAttr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  } else {
    VarAttr = EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  }

  //
  // Get Cert Database content from variable
  //
  Status = AuthServiceInternalFindVariable (
             DbName,
             &gEfiCertDbGuid,
             (VOID **) &Data,
             &DataSize
             );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((DataSize == 0) || (Data == NULL)) {
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  if (DataSize == sizeof (UINT32)) {
    //
    // There is no certs in Cert Database
    //
    return EFI_SUCCESS;
  }


  Status = FindCertsFromDb (
             VariableName,
             VendorGuid,
             Attributes,
             Data,
             DataSize,
             NULL,
             NULL,
             &CertNodeOffset,
             &CertNodeSize,
             NULL,
             NULL,
             NULL
             );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (DataSize < (CertNodeOffset + CertNodeSize)) {
    return EFI_NOT_FOUND;
  }

  //
  // Construct new data content of Cert Database
  //
  NewCertDbSize = (UINT32) DataSize - CertNodeSize;
  NewCertDb     = (UINT8*) mCertDbStore;

  //
  // Copy the DB entries before deleting node.
  //
  CopyMem (NewCertDb, Data, CertNodeOffset);
  //
  // Update CertDbListSize.
  //
  CopyMem (NewCertDb, &NewCertDbSize, sizeof (UINT32));
  //
  // Copy the DB entries after deleting node.
  //
  if (DataSize > (CertNodeOffset + CertNodeSize)) {
    CopyMem (
      NewCertDb + CertNodeOffset,
      Data + CertNodeOffset + CertNodeSize,
      DataSize - CertNodeOffset - CertNodeSize
      );
  }

  //
  // Update Cert Database content to variable
  //
  Status   = AuthServiceInternalUpdateVariable (
               DbName,
               &gEfiCertDbGuid,
               NewCertDb,
               NewCertDbSize,
               VarAttr
               );

  return Status;
}

/**
  Insert signer's certificates for common authenticated variable with VariableName
  and VendorGuid in AUTH_CERT_DB_DATA to "certdb" or "certdbv" according to
  time based authenticated variable attributes. CertData is the SHA256 digest of
  SignerCert CommonName + TopLevelCert tbsCertificate.

  @param[in]  VariableName      Name of authenticated Variable.
  @param[in]  VendorGuid        Vendor GUID of authenticated Variable.
  @param[in]  Attributes        Attributes of authenticated variable.
  @param[in]  SignerCert        Signer certificate data.
  @param[in]  SignerCertSize    Length of signer certificate.
  @param[in]  TopLevelCert      Top-level certificate data.
  @param[in]  TopLevelCertSize  Length of top-level certificate.

  @retval  EFI_INVALID_PARAMETER Any input parameter is invalid.
  @retval  EFI_ACCESS_DENIED     An AUTH_CERT_DB_DATA entry with same VariableName
                                 and VendorGuid already exists.
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           Insert an AUTH_CERT_DB_DATA entry to "certdb" or "certdbv"

**/
EFI_STATUS
InsertCertsToDb (
  IN     CHAR16           *VariableName,
  IN     EFI_GUID         *VendorGuid,
  IN     UINT32           Attributes,
  IN     UINT8            *SignerCert,
  IN     UINTN            SignerCertSize,
  IN     UINT8            *TopLevelCert,
  IN     UINTN            TopLevelCertSize,
  IN     UINT8            *NonceData,   OPTIONAL
  IN     UINTN            NonceDataSize
  )
{
  EFI_STATUS              Status;
  UINT8                   *Data;
  UINT8                   Type;
  UINTN                   DataSize;
  UINT32                  VarAttr;
  UINT8                   *NewCertDb;
  UINT32                  NewCertDbSize;
  UINT32                  CertNodeOffset;
  UINT32                  CertNodeSize;
  UINT32                  NameSize;
  UINT32                  CertDataSize;
  AUTH_CERT_DB_DATA       *Ptr;
  CHAR16                  *DbName;
  UINT8                   Sha256Digest[SHA256_DIGEST_SIZE];
  BOOLEAN                 IsCertDataUpdate;
  BOOLEAN                 IsSelfGenRand;
  UINT32                  Rand;

  if ((VariableName == NULL) || (VendorGuid == NULL) || (SignerCert == NULL) ||(TopLevelCert == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get Cert Database name by variable attributes
  //
  Status = GetCertDatabaseName(Attributes, &DbName);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if ((Attributes & EFI_VARIABLE_NON_VOLATILE) != 0) {
    VarAttr  = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  } else {
    VarAttr = EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  }

  //
  // Get Cert Database content from variable
  //
  Status = AuthServiceInternalFindVariable (
             DbName,
             &gEfiCertDbGuid,
             (VOID **) &Data,
             &DataSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((DataSize == 0) || (Data == NULL)) {
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  //
  // Find whether matching cert node already exists in Cert Database.
  // If yes return error.
  //
  Status = FindCertsFromDb (
             VariableName,
             VendorGuid,
             Attributes,
             Data,
             DataSize,
             NULL,
             NULL,
             &CertNodeOffset,
             &CertNodeSize,
             NULL,
             NULL,
             NULL
             );

  if (!EFI_ERROR (Status) && ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0)) {
    ASSERT (FALSE);
    return EFI_ACCESS_DENIED;
  } else if (!EFI_ERROR (Status) && (Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
    //
    // Delete existing cert info for Enhanced Auth Variable
    //
    NewCertDbSize = (UINT32) DataSize - CertNodeSize;
    NewCertDb     = (UINT8*) mCertDbStore;

    //
    // Copy the DB entries before deleting node.
    //
    CopyMem (NewCertDb, Data, CertNodeOffset);

    //
    // Skip CertDbListSize Update, leave it to Cert Insert .
    //

    //
    // Copy the DB entries after deleting node.
    //
    if (DataSize > (CertNodeOffset + CertNodeSize)) {
      CopyMem (
        NewCertDb + CertNodeOffset,
        Data + CertNodeOffset + CertNodeSize,
        DataSize - CertNodeOffset - CertNodeSize
        );
    }

    DataSize     = NewCertDbSize;
    IsCertDataUpdate = TRUE;
  } else {
    IsCertDataUpdate = FALSE;
  }

  //
  // Construct new Cert Database content 
  //
  NameSize      = (UINT32) StrLen (VariableName);
  CertDataSize  = sizeof(Sha256Digest);
  CertNodeSize  = SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertDataSize);
  IsSelfGenRand = FALSE;
  if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
    if (NonceDataSize == 0) {
      Type = EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE;
    } else {
      if (IsZeroNonce(NonceData, NonceDataSize)) {
        //
        // Generate 32bit Nonce by default
        //
        if (!GetRandomNumber32(&Rand)) {
          return EFI_UNSUPPORTED;
        }
        NonceDataSize = sizeof(Rand);
        IsSelfGenRand = TRUE;
      }
      Type = EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE;
    }
    CertNodeSize += sizeof(UINT8) + sizeof(UINT32) + (UINT32)NonceDataSize;
  }

  NewCertDbSize = (UINT32) DataSize + CertNodeSize;
  if (NewCertDbSize > mMaxCertDbSize) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = CalculatePrivAuthVarSignChainSHA256Digest(
             SignerCert,
             SignerCertSize,
             TopLevelCert,
             TopLevelCertSize,
             Sha256Digest
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // In cert info update case,  NewCertDb already points to scratch buffer containing updated data
  //
  if (IsCertDataUpdate == FALSE) {
    NewCertDb     = (UINT8*) mCertDbStore;
    DEBUG((DEBUG_INFO, "NewCertDb %x\n", NewCertDb));
    //
    // Copy the DB entries before inserting node.
    //
    CopyMem (NewCertDb, Data, DataSize);
  }

  //
  // Update CertDbListSize.
  //
  CopyMem (NewCertDb, &NewCertDbSize, sizeof (UINT32));
  //
  // Construct new cert node.
  //
  Ptr = (AUTH_CERT_DB_DATA *) (NewCertDb + DataSize);
  CopyGuid (&Ptr->VendorGuid, VendorGuid);
  CopyMem (&Ptr->CertNodeSize, &CertNodeSize, sizeof (UINT32));
  CopyMem (&Ptr->NameSize, &NameSize, sizeof (UINT32));
  CopyMem (&Ptr->CertDataSize, &CertDataSize, sizeof (UINT32));

  CopyMem (
    (UINT8 *) Ptr + sizeof (AUTH_CERT_DB_DATA),
    VariableName,
    NameSize * sizeof (CHAR16)
    );

  CopyMem (
    (UINT8 *) Ptr +  sizeof (AUTH_CERT_DB_DATA) + NameSize * sizeof (CHAR16),
    Sha256Digest,
    CertDataSize
    );

  //
  // Copy Type for Enhanced Auth Variable
  //
  if ((Attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS) != 0) {
    CopyMem (
      (UINT8 *) Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertDataSize),
      &Type,
      sizeof(UINT8)
      );

    //
    // Still store NonceSize for Timstamp type for future extension
    //
    CopyMem (
      (UINT8 *) Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertDataSize) + sizeof(UINT8),
      &NonceDataSize,
      sizeof(UINT32)
      );

    if (NonceDataSize != 0) {
      if (IsSelfGenRand == FALSE) {
        CopyMem (
          (UINT8 *) Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertDataSize) + sizeof(UINT8) + sizeof(UINT32),
          NonceData,
          NonceDataSize
          );
      } else {
        CopyMem (
          (UINT8 *) Ptr + SIZE_OF_AUTH_CERT_DB_DATA(NameSize, CertDataSize) + sizeof(UINT8) + sizeof(UINT32),
          &Rand,
          NonceDataSize
          );
      }
    }
  }

  //
  // Update Cert Database content to variable
  //
  Status   = AuthServiceInternalUpdateVariable (
               DbName,
               &gEfiCertDbGuid,
               NewCertDb,
               NewCertDbSize,
               VarAttr
               );

  return Status;
}

/**
  Clean up signer's certificates for common authenticated variable
  by corresponding VariableName and VendorGuid from "certdb".
  System may break down during Timebased Variable update & certdb update,
  make them inconsistent,  this function is called in AuthVariable Init
  to ensure consistency.

  @retval  EFI_NOT_FOUND         Fail to find variable "certdb".
  @retval  EFI_OUT_OF_RESOURCES  The operation is failed due to lack of resources.
  @retval  EFI_SUCCESS           The operation is completed successfully.

**/
EFI_STATUS
CleanCertsFromDb (
  IN  CHAR16         *DatabaseName,
  IN  EFI_GUID       *DatabaseVendorGuid,
  IN  UINT32         AuthAttributes
  )
{
  UINT32                  Offset;
  AUTH_CERT_DB_DATA       *Ptr;
  UINT32                  NameSize;
  UINT32                  NodeSize;
  CHAR16                  *VariableName;
  EFI_STATUS              Status;
  BOOLEAN                 CertCleaned;
  UINT8                   *Data;
  UINTN                   DataSize;
  EFI_GUID                AuthVarGuid;
  AUTH_VARIABLE_INFO      AuthVariableInfo;

  Status = EFI_SUCCESS;

  //
  // Get corresponding certificates by VendorGuid and VariableName.
  //
  do {
    CertCleaned = FALSE;

    //
    // Get latest Cert Database from variable
    //
    Status = AuthServiceInternalFindVariable (
               DatabaseName,
               DatabaseVendorGuid,
               (VOID **) &Data,
               &DataSize
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if ((DataSize == 0) || (Data == NULL)) {
      ASSERT (FALSE);
      return EFI_NOT_FOUND;
    }
  
    Offset = sizeof (UINT32);
  
    while (Offset < (UINT32) DataSize) {
      Ptr = (AUTH_CERT_DB_DATA *) (Data + Offset);
      NodeSize = ReadUnaligned32 (&Ptr->CertNodeSize);
      NameSize = ReadUnaligned32 (&Ptr->NameSize);

      //
      // Get VarName tailed with '\0'
      //
      VariableName = AllocateZeroPool((NameSize + 1) * sizeof(CHAR16));
      if (VariableName == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem (VariableName, (UINT8 *) Ptr + sizeof (AUTH_CERT_DB_DATA), NameSize * sizeof(CHAR16));
      //
      // Keep VarGuid  aligned
      //
      CopyMem (&AuthVarGuid, &Ptr->VendorGuid, sizeof(EFI_GUID));

      //
      // Find corresponding auth variable
      //
      ZeroMem (&AuthVariableInfo, sizeof (AuthVariableInfo));
      Status = mAuthVarLibContextIn->FindVariable (
                                       VariableName,
                                       &AuthVarGuid,
                                       &AuthVariableInfo
                                       );
      //
      // If corresponding variabe doesn't exist or Attributes is not consistent to Cert database
      //
      if (EFI_ERROR(Status) || ((AuthVariableInfo.Attributes & AuthAttributes) == 0)) {
        //
        // This Cert is for a NV Authenticated Variables(VariableName, AuthVarGuid, Auth Attribute same as AuthAttributes)
        // The variable doesn't exist anymore. Clear the corresponding Cert in Cert Database
        //
        Status      = DeleteCertsFromDb(
                        VariableName,
                        &AuthVarGuid,
                        AuthAttributes | EFI_VARIABLE_NON_VOLATILE
                        );
        CertCleaned = TRUE;
        DEBUG((EFI_D_INFO, "Recovery!! Cert for Auth Variable %s Guid %g is removed from %s for consistency\n", VariableName, &AuthVarGuid, DatabaseName));
        FreePool(VariableName);
        break;
      }

      FreePool(VariableName);
      Offset = Offset + NodeSize;
    }
  } while (CertCleaned);

  return Status;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[in]  OrgTimeStamp                Pointer to original time stamp,
                                          original variable is not found if NULL.
  @param[out]  VarPayloadPtr              Pointer to variable payload address.
  @param[out]  VarPayloadSize             Pointer to variable payload size.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyTimeBasedPayload (
  IN     CHAR16                             *VariableName,
  IN     EFI_GUID                           *VendorGuid,
  IN     VOID                               *Data,
  IN     UINTN                              DataSize,
  IN     UINT32                             Attributes,
  IN     AUTHVAR_TYPE                       AuthVarType,
  IN     EFI_TIME                           *OrgTimeStamp,
  OUT    UINT8                              **VarPayloadPtr,
  OUT    UINTN                              *VarPayloadSize
  )
{
  EFI_VARIABLE_AUTHENTICATION_2    *CertData;
  UINT8                            *SigData;
  UINT32                           SigDataSize;
  UINT8                            *PayloadPtr;
  UINTN                            PayloadSize;
  UINT32                           Attr;
  BOOLEAN                          VerifyStatus;
  EFI_STATUS                       Status;
  EFI_SIGNATURE_LIST               *CertList;
  EFI_SIGNATURE_DATA               *Cert;
  UINTN                            Index;
  UINTN                            CertCount;
  UINT32                           KekDataSize;
  UINT8                            *NewData;
  UINTN                            NewDataSize;
  UINT8                            *Buffer;
  UINTN                            Length;
  UINT8                            *TopLevelCert;
  UINTN                            TopLevelCertSize;
  UINT8                            *TrustedCert;
  UINTN                            TrustedCertSize;
  UINT8                            *SignerCerts;
  UINTN                            CertStackSize;
  UINT8                            *CertsInCertDb;
  UINT32                           CertsSizeinDb;
  UINT8                            Sha256Digest[SHA256_DIGEST_SIZE];
  EFI_CERT_DATA                    *CertDataPtr;

  //
  // 1. TopLevelCert is the top-level issuer certificate in signature Signer Cert Chain
  // 2. TrustedCert is the certificate which firmware trusts. It could be saved in protected
  //     storage or PK payload on PK init
  //
  VerifyStatus           = FALSE;
  CertData               = NULL;
  NewData                = NULL;
  Attr                   = Attributes;
  SignerCerts            = NULL;
  TopLevelCert           = NULL;
  CertsInCertDb          = NULL;
  CertDataPtr            = NULL;

  //
  // When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
  // set, then the Data buffer shall begin with an instance of a complete (and serialized)
  // EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new
  // variable value and DataSize shall reflect the combined size of the descriptor and the new
  // variable value. The authentication descriptor is not part of the variable data and is not
  // returned by subsequent calls to GetVariable().
  //
  CertData = (EFI_VARIABLE_AUTHENTICATION_2 *) Data;

  //
  // Verify that Pad1, Nanosecond, TimeZone, Daylight and Pad2 components of the
  // TimeStamp value are set to zero.
  //
  if ((CertData->TimeStamp.Pad1 != 0) ||
      (CertData->TimeStamp.Nanosecond != 0) ||
      (CertData->TimeStamp.TimeZone != 0) ||
      (CertData->TimeStamp.Daylight != 0) ||
      (CertData->TimeStamp.Pad2 != 0)) {
    return EFI_SECURITY_VIOLATION;
  }

  if ((OrgTimeStamp != NULL) && ((Attributes & EFI_VARIABLE_APPEND_WRITE) == 0)) {
    if (AuthServiceInternalCompareTimeStamp (&CertData->TimeStamp, OrgTimeStamp)) {
      //
      // TimeStamp check fail, suspicious replay attack, return EFI_SECURITY_VIOLATION.
      //
      return EFI_SECURITY_VIOLATION;
    }
  }

  //
  // wCertificateType should be WIN_CERT_TYPE_EFI_GUID.
  // Cert type should be EFI_CERT_TYPE_PKCS7_GUID.
  //
  if ((CertData->AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID) ||
      !CompareGuid (&CertData->AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
    //
    // Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
    //
    return EFI_SECURITY_VIOLATION;
  }

  //
  // Find out Pkcs7 SignedData which follows the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
  // AuthInfo.Hdr.dwLength is the length of the entire certificate, including the length of the header.
  //
  SigData = CertData->AuthInfo.CertData;
  SigDataSize = CertData->AuthInfo.Hdr.dwLength - (UINT32) (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData));

  //
  // SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the
  // signature. Only a digest algorithm of SHA-256 is accepted.
  //
  //    According to PKCS#7 Definition:
  //        SignedData ::= SEQUENCE {
  //            version Version,
  //            digestAlgorithms DigestAlgorithmIdentifiers,
  //            contentInfo ContentInfo,
  //            .... }
  //    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm 
  //    in VARIABLE_AUTHENTICATION_2 descriptor.
  //    This field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
  //
  if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
    if (SigDataSize >= (13 + sizeof (mSha256OidValue))) {
      if (((*(SigData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) || 
           (CompareMem (SigData + 13, &mSha256OidValue, sizeof (mSha256OidValue)) != 0)) {
          return EFI_SECURITY_VIOLATION;
        }
    }
  }

  //
  // Find out the new data payload which follows Pkcs7 SignedData directly.
  //
  PayloadPtr = SigData + SigDataSize;
  PayloadSize = DataSize - OFFSET_OF_AUTHINFO2_CERT_DATA - (UINTN) SigDataSize;

  //
  // Construct a serialization buffer of the values of the VariableName, VendorGuid and Attributes
  // parameters of the SetVariable() call and the TimeStamp component of the
  // EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable's new value
  // i.e. (VariableName, VendorGuid, Attributes, TimeStamp, Data)
  //
  NewDataSize = PayloadSize + sizeof (EFI_TIME) + sizeof (UINT32) +
                sizeof (EFI_GUID) + StrSize (VariableName) - sizeof (CHAR16);

  //
  // Here is to reuse scratch data area(at the end of volatile variable store)
  // to reduce SMRAM consumption for SMM variable driver.
  // The scratch buffer is enough to hold the serialized data and safe to use,
  // because it is only used at here to do verification temporarily first
  // and then used in UpdateVariable() for a time based auth variable set.
  //
  Status = mAuthVarLibContextIn->GetScratchBuffer (&NewDataSize, (VOID **) &NewData);
  if (EFI_ERROR (Status)) {
    return EFI_OUT_OF_RESOURCES;
  }

  Buffer = NewData;
  Length = StrLen (VariableName) * sizeof (CHAR16);
  CopyMem (Buffer, VariableName, Length);
  Buffer += Length;

  Length = sizeof (EFI_GUID);
  CopyMem (Buffer, VendorGuid, Length);
  Buffer += Length;

  Length = sizeof (UINT32);
  CopyMem (Buffer, &Attr, Length);
  Buffer += Length;

  Length = sizeof (EFI_TIME);
  CopyMem (Buffer, &CertData->TimeStamp, Length);
  Buffer += Length;

  CopyMem (Buffer, PayloadPtr, PayloadSize);

  if (AuthVarType == AuthVarTypePk) {
    //
    // Verify that the signature has been made with the current Platform Key (no chaining for PK).
    // First, get signer's certificates from SignedData.
    //
    VerifyStatus = Pkcs7GetSigners (
                     SigData,
                     SigDataSize,
                     &SignerCerts,
                     &CertStackSize,
                     &TopLevelCert,
                     &TopLevelCertSize
                     );
    if (!VerifyStatus) {
      goto Exit;
    }

    //
    // Second, get the current platform key from variable. Check whether it's identical with signer's certificates
    // in SignedData. If not, return error immediately.
    //
    Status = AuthServiceInternalFindVariable (
               EFI_PLATFORM_KEY_NAME,
               &gEfiGlobalVariableGuid,
               &Data,
               &DataSize
               );
    if (EFI_ERROR (Status)) {
      VerifyStatus = FALSE;
      goto Exit;
    }
    CertList = (EFI_SIGNATURE_LIST *) Data;
    Cert     = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
    if ((TopLevelCertSize != (CertList->SignatureSize - (sizeof (EFI_SIGNATURE_DATA) - 1))) ||
        (CompareMem (Cert->SignatureData, TopLevelCert, TopLevelCertSize) != 0)) {
      VerifyStatus = FALSE;
      goto Exit;
    }

    //
    // Verify Pkcs7 SignedData via Pkcs7Verify library.
    //
    VerifyStatus = Pkcs7Verify (
                     SigData,
                     SigDataSize,
                     TopLevelCert,
                     TopLevelCertSize,
                     NewData,
                     NewDataSize
                     );

  } else if (AuthVarType == AuthVarTypeKek) {

    //
    // Get KEK database from variable.
    //
    Status = AuthServiceInternalFindVariable (
               EFI_KEY_EXCHANGE_KEY_NAME,
               &gEfiGlobalVariableGuid,
               &Data,
               &DataSize
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Ready to verify Pkcs7 SignedData. Go through KEK Signature Database to find out X.509 CertList.
    //
    KekDataSize      = (UINT32) DataSize;
    CertList         = (EFI_SIGNATURE_LIST *) Data;
    while ((KekDataSize > 0) && (KekDataSize >= CertList->SignatureListSize)) {
      if (CompareGuid (&CertList->SignatureType, &gEfiCertX509Guid)) {
        Cert       = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
        CertCount  = (CertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
        for (Index = 0; Index < CertCount; Index++) {
          //
          // Iterate each Signature Data Node within this CertList for a verify
          //
          TrustedCert      = Cert->SignatureData;
          TrustedCertSize  = CertList->SignatureSize - (sizeof (EFI_SIGNATURE_DATA) - 1);

          //
          // Verify Pkcs7 SignedData via Pkcs7Verify library.
          //
          VerifyStatus = Pkcs7Verify (
                           SigData,
                           SigDataSize,
                           TrustedCert,
                           TrustedCertSize,
                           NewData,
                           NewDataSize
                           );
          if (VerifyStatus) {
            goto Exit;
          }
          Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
        }
      }
      KekDataSize -= CertList->SignatureListSize;
      CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
    }
  } else if (AuthVarType == AuthVarTypePriv) {

    //
    // Process common authenticated variable except PK/KEK/DB/DBX/DBT.
    // Get signer's certificates from SignedData.
    //
    VerifyStatus = Pkcs7GetSigners (
                     SigData,
                     SigDataSize,
                     &SignerCerts,
                     &CertStackSize,
                     &TopLevelCert,
                     &TopLevelCertSize
                     );
    if (!VerifyStatus) {
      goto Exit;
    }

    //
    // Get previously stored signer's certificates from certdb or certdbv for existing
    // variable. Check whether they are identical with signer's certificates
    // in SignedData. If not, return error immediately.
    //
    if (OrgTimeStamp != NULL) {
      VerifyStatus = FALSE;

      Status = GetCertsFromDb (VariableName, VendorGuid, Attributes, &CertsInCertDb, &CertsSizeinDb, NULL, NULL, NULL);
      if (EFI_ERROR (Status)) {
        goto Exit;
      }

      if (CertsSizeinDb == SHA256_DIGEST_SIZE) {
        //
        // Check hash of signer cert CommonName + Top-level issuer tbsCertificate against data in CertDb
        //
        CertDataPtr = (EFI_CERT_DATA *)(SignerCerts + 1);
        Status = CalculatePrivAuthVarSignChainSHA256Digest(
                   CertDataPtr->CertDataBuffer,
                   ReadUnaligned32 ((UINT32 *)&(CertDataPtr->CertDataLength)),
                   TopLevelCert,
                   TopLevelCertSize,
                   Sha256Digest
                   );
        if (EFI_ERROR(Status) || CompareMem (Sha256Digest, CertsInCertDb, CertsSizeinDb) != 0){
          goto Exit;
        }
      } else {
         //
         // Keep backward compatible with previous solution which saves whole signer certs stack in CertDb
         //
         if ((CertStackSize != CertsSizeinDb) ||
             (CompareMem (SignerCerts, CertsInCertDb, CertsSizeinDb) != 0)) {
              goto Exit;
         }
      }
    }

    VerifyStatus = Pkcs7Verify (
                     SigData,
                     SigDataSize,
                     TopLevelCert,
                     TopLevelCertSize,
                     NewData,
                     NewDataSize
                     );
    if (!VerifyStatus) {
      goto Exit;
    }

    if ((OrgTimeStamp == NULL) && (PayloadSize != 0)) {
      //
      // When adding a new common authenticated variable, always save Hash of cn of signer cert + tbsCertificate of Top-level issuer
      //
      CertDataPtr = (EFI_CERT_DATA *)(SignerCerts + 1);
      Status = InsertCertsToDb (
                 VariableName,
                 VendorGuid,
                 Attributes,
                 CertDataPtr->CertDataBuffer,
                 ReadUnaligned32 ((UINT32 *)&(CertDataPtr->CertDataLength)),
                 TopLevelCert,
                 TopLevelCertSize,
                 NULL,
                 0
                 );
      if (EFI_ERROR (Status)) {
        VerifyStatus = FALSE;
        goto Exit;
      }
    }
  } else if (AuthVarType == AuthVarTypePayload) {
    CertList = (EFI_SIGNATURE_LIST *) PayloadPtr;
    Cert     = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
    TrustedCert     = Cert->SignatureData;
    TrustedCertSize = CertList->SignatureSize - (sizeof (EFI_SIGNATURE_DATA) - 1);
    //
    // Verify Pkcs7 SignedData via Pkcs7Verify library.
    //
    VerifyStatus = Pkcs7Verify (
                     SigData,
                     SigDataSize,
                     TrustedCert,
                     TrustedCertSize,
                     NewData,
                     NewDataSize
                     );
  } else {
    return EFI_SECURITY_VIOLATION;
  }

Exit:

  if (AuthVarType == AuthVarTypePk || AuthVarType == AuthVarTypePriv) {
    Pkcs7FreeSigners (TopLevelCert);
    Pkcs7FreeSigners (SignerCerts);
  }

  if (!VerifyStatus) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = CheckSignatureListFormat(VariableName, VendorGuid, PayloadPtr, PayloadSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *VarPayloadPtr = PayloadPtr;
  *VarPayloadSize = PayloadSize;

  return EFI_SUCCESS;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[out] VarDel                      Delete the variable or not.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyTimeBasedPayloadAndUpdate (
  IN     CHAR16                             *VariableName,
  IN     EFI_GUID                           *VendorGuid,
  IN     VOID                               *Data,
  IN     UINTN                              DataSize,
  IN     UINT32                             Attributes,
  IN     AUTHVAR_TYPE                       AuthVarType,
  OUT    BOOLEAN                            *VarDel
  )
{
  EFI_STATUS                       Status;
  EFI_STATUS                       FindStatus;
  UINT8                            *PayloadPtr;
  UINTN                            PayloadSize;
  EFI_VARIABLE_AUTHENTICATION_2    *CertData;
  AUTH_VARIABLE_INFO               OrgVariableInfo;
  BOOLEAN                          IsDel;

  ZeroMem (&OrgVariableInfo, sizeof (OrgVariableInfo));
  FindStatus = mAuthVarLibContextIn->FindVariable (
             VariableName,
             VendorGuid,
             &OrgVariableInfo
             );

  Status = VerifyTimeBasedPayload (
             VariableName,
             VendorGuid,
             Data,
             DataSize,
             Attributes,
             AuthVarType,
             (!EFI_ERROR (FindStatus)) ? OrgVariableInfo.TimeStamp : NULL,
             &PayloadPtr,
             &PayloadSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!EFI_ERROR(FindStatus)
   && (PayloadSize == 0)
   && ((Attributes & EFI_VARIABLE_APPEND_WRITE) == 0)) {
    IsDel = TRUE;
  } else {
    IsDel = FALSE;
  }

  CertData = (EFI_VARIABLE_AUTHENTICATION_2 *) Data;

  //
  // Final step: Update/Append Variable if it pass Pkcs7Verify
  //
  Status = AuthServiceInternalUpdateVariableWithTimeStamp (
             VariableName,
             VendorGuid,
             PayloadPtr,
             PayloadSize,
             Attributes,
             &CertData->TimeStamp
             );

  //
  // Delete signer's certificates when delete the common authenticated variable.
  //
  if (IsDel && AuthVarType == AuthVarTypePriv && !EFI_ERROR(Status) ) {
    Status = DeleteCertsFromDb (VariableName, VendorGuid, Attributes);
  }

  if (VarDel != NULL) {
    if (IsDel && !EFI_ERROR(Status)) {
      *VarDel = TRUE;
    } else {
      *VarDel = FALSE;
    }
  }

  return Status;
}

EFI_STATUS
VerifyNewCert(
  IN   UINT8      *Data,
  IN   UINTN      DataSize,
  OUT  UINT8      **SignerCerts,
  OUT  UINTN      *CertStackSize,
  OUT  UINT8      **TopLevelCert,
  OUT  UINTN      *TopLevelCertSize
  )
{
  BOOLEAN         VerifyStatus;
  EFI_STATUS      Status;
  UINT8           *SigData;
  UINT32          SigDataSize;
  UINT32          DwLength;
  UINT8           *NewCertContent;
  UINTN           NewCertContentSize;
  UINT16          wCertificateType;
  UINT8           *TbsCert;
  UINTN           TbsCertSize;
  EFI_CERT_DATA   *CertDataPtr;

  DEBUG((DEBUG_INFO, "Verify NewCert(WIN_CERTIFICATE_UEFI_GUID) %x DataSize %x\n", Data, DataSize));

  Status        = EFI_SUCCESS;
  *SignerCerts  = NULL;
  *TopLevelCert = NULL;
  DwLength      = ReadUnaligned32((UINT32 *)(Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, Hdr) + OFFSET_OF(WIN_CERTIFICATE, dwLength)));
  SigDataSize   = DwLength - (UINT32) (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData));
  SigData       = Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);

  //
  // 1. Check WIN_CERTIFICATE_UEFI_GUID structure
  //
  wCertificateType = ReadUnaligned16((UINT16 *)(Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, Hdr) + OFFSET_OF(WIN_CERTIFICATE, wCertificateType)));
  if (wCertificateType != WIN_CERT_TYPE_EFI_GUID ||
      !CompareGuid ((EFI_GUID *)(Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertType)), &gEfiCertPkcs7Guid)) {
    //
    // Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
    //
    return EFI_SECURITY_VIOLATION;
  }


  //
  // 2. SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the
  // signature. Only a digest algorithm of SHA-256 is accepted.
  //
  //    According to PKCS#7 Definition:
  //        SignedData ::= SEQUENCE {
  //            version Version,
  //            digestAlgorithms DigestAlgorithmIdentifiers,
  //            contentInfo ContentInfo,
  //            .... }
  //    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm 
  //    in VARIABLE_AUTHENTICATION_2 descriptor.
  //    This field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
  //
  if (SigDataSize >= (13 + sizeof (mSha256OidValue))) {
    if (((*(SigData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) || 
         (CompareMem (SigData + 13, &mSha256OidValue, sizeof (mSha256OidValue)) != 0)) {
        return EFI_SECURITY_VIOLATION;
      }
  }


  //
  // 3. Verify SignedData. It is a embedded signature type
  //
  //    3.1 Get data from Content element. ContentType OID is 1.2.840.113549.1.7.1
  //
  VerifyStatus = Pkcs7GetAttachedContent (
                   SigData,
                   SigDataSize,
                   &NewCertContent,
                   &NewCertContentSize
                   );
  if (!VerifyStatus) {
    DEBUG((DEBUG_ERROR, "Pkcs7GetAttachedContent for NewCert failed\n"));
    goto EXIT;
  }

  //
  //    3.2 Ensure tbsCertificate in Content matches with tbsCertificate in SigningCert 
  //
  VerifyStatus = Pkcs7GetSigners (
                   SigData,
                   SigDataSize,
                   SignerCerts,
                   CertStackSize,
                   TopLevelCert,
                   TopLevelCertSize
                   );
  if (!VerifyStatus) {
    DEBUG((DEBUG_ERROR, "Pkcs7GetSigners for NewCert failed\n"));
    goto EXIT;
  }

  CertDataPtr = (EFI_CERT_DATA *)(*SignerCerts + sizeof(EFI_CERT_STACK));
  if (!X509GetTBSCert(CertDataPtr->CertDataBuffer, ReadUnaligned32 ((UINT32 *)&(CertDataPtr->CertDataLength)), &TbsCert, &TbsCertSize)) {
    DEBUG((DEBUG_INFO, "%a Get Signer Cert tbsCertificate failed!\n", __FUNCTION__));
    return EFI_SECURITY_VIOLATION;
  }

  if (TbsCertSize != NewCertContentSize || CompareMem(NewCertContent, TbsCert, NewCertContentSize) != 0) {
    DEBUG((DEBUG_INFO, "%a Signer Cert tbsCertificate doesn't match ContentInfo!\n", __FUNCTION__));
    return EFI_SECURITY_VIOLATION;
  }

  //
  //    3.3 Verify NewCert PKCS7 SignedData
  //
  VerifyStatus = Pkcs7Verify (
                   SigData,
                   SigDataSize,
                   *TopLevelCert,
                   *TopLevelCertSize,
                   NewCertContent,
                   NewCertContentSize
                   );
  if (!VerifyStatus) {
    DEBUG((DEBUG_ERROR, "Pkcs7Verify for NewCert failed\n"));
  }

EXIT:
  if (NewCertContent != NULL) {
    //
    // Caution!!, may need to update according to 
    // Since iNewCertContent is using AllocatePool 
    //
    Pkcs7FreeSigners(NewCertContent);
  }

  if (!VerifyStatus) {
    Status = EFI_SECURITY_VIOLATION;
    //
    // Signer, TopLevel certs are required by Caller. Do not free them if verify succeed.
    //
    Pkcs7FreeSigners(*SignerCerts);
    Pkcs7FreeSigners(*TopLevelCert);

    *SignerCerts = NULL;
    *TopLevelCert = NULL;
  }

  return Status;
}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[in]  OrgTimeStamp                Pointer to original time stamp,
                                          original variable is not found if NULL.
  @param[out]  VarPayloadPtr              Pointer to variable payload address.
  @param[out]  VarPayloadSize             Pointer to variable payload size.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifySigningCert (
  IN     CHAR16                             *VariableName,
  IN     EFI_GUID                           *VendorGuid,
  IN     UINT8                              *Data,
  IN     UINTN                              DataSize,
  IN     UINT8                              *TrustedCertData,  OPTIONAL
  IN     UINTN                              TrustedCertDataSize,
  IN     UINT32                             Attributes,
  IN     EFI_TIME                           *NewTimeStamp,  OPTIONAL
  IN     UINT8                              *OrigNonce,     OPTIONAL
  IN     UINTN                              OrigNonceSize,  
  IN     UINT8                              *NewNonce,      OPTIONAL
  IN     UINTN                              NewNonceSize,   
  IN     UINT8                              *NewCert,       OPTIONAL
  IN     UINTN                              NewCertSize,    
  IN     UINT8                              *Payload,
  IN     UINTN                              PayloadSize
  )
{

  BOOLEAN            VerifyStatus;
  EFI_STATUS         Status;
  UINT8              *SigData;
  UINT32             SigDataSize;
  UINTN              Length;
  UINT8              *NewCertContent;
  UINTN              NewCertContentSize;
  UINT16             wCertificateType;
  EFI_CERT_DATA      *CertDataPtr;
  UINT8              *SignerCerts;
  UINTN              CertStackSize;
  UINT8              *TopLevelCert;
  UINTN              TopLevelCertSize;
  UINT8              *Buffer;
  UINT8              Sha256Digest[SHA256_DIGEST_SIZE];
  EFI_VARIABLE_AUTHENTICATION_3_NONCE  Auth3Nonce;

  DEBUG((DEBUG_INFO, "Verify SigningCert(WIN_CERTIFICATE_UEFI_GUID) %x DataSize %x\n", Data, DataSize));

  Status        = EFI_SUCCESS;
  SignerCerts   = NULL;
  TopLevelCert  = NULL;
  SigData       = Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
  SigDataSize   = (UINT32)(DataSize -  OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData));

  //
  // 1. Check WIN_CERTIFICATE_UEFI_GUID structure
  //
  wCertificateType = ReadUnaligned16((UINT16 *)(Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, Hdr) + OFFSET_OF(WIN_CERTIFICATE, wCertificateType)));
  if (wCertificateType != WIN_CERT_TYPE_EFI_GUID ||
      !CompareGuid ((EFI_GUID *)(Data + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertType)), &gEfiCertPkcs7Guid)) {
    //
    // Invalid AuthInfo type, return EFI_SECURITY_VIOLATION.
    //
    return EFI_SECURITY_VIOLATION;
  }


  //
  // 2. SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the
  // signature. Only a digest algorithm of SHA-256 is accepted.
  //
  //    According to PKCS#7 Definition:
  //        SignedData ::= SEQUENCE {
  //            version Version,
  //            digestAlgorithms DigestAlgorithmIdentifiers,
  //            contentInfo ContentInfo,
  //            .... }
  //    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm 
  //    in VARIABLE_AUTHENTICATION_2 descriptor.
  //    This field has the fixed offset (+13) and be calculated based on two bytes of length encoding.
  //
  if (SigDataSize >= (13 + sizeof (mSha256OidValue))) {
    if (((*(SigData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE) || 
         (CompareMem (SigData + 13, &mSha256OidValue, sizeof (mSha256OidValue)) != 0)) {
        return EFI_SECURITY_VIOLATION;
      }
  }

  //
  // 3. Confirm Signer Certs Stack in SigningCert is trusted. 
  //     Skip TrustedCertData check, when Variable was created at the first time(TrustedCertData == NULL).
  //
  VerifyStatus = Pkcs7GetSigners (
                   SigData,
                   SigDataSize,
                   &SignerCerts,
                   &CertStackSize,
                   &TopLevelCert,
                   &TopLevelCertSize
                   );
  if (!VerifyStatus) {
    DEBUG((DEBUG_ERROR, "Pkcs7GetSigners for NewCert failed\n"));
    Status = EFI_SECURITY_VIOLATION;
    goto EXIT;
  }

  if (TrustedCertData != NULL) {
    CertDataPtr = (EFI_CERT_DATA *)(SignerCerts + sizeof(EFI_CERT_STACK));
    Status = CalculatePrivAuthVarSignChainSHA256Digest(
               CertDataPtr->CertDataBuffer,
               ReadUnaligned32 ((UINT32 *)&(CertDataPtr->CertDataLength)),
               TopLevelCert,
               TopLevelCertSize,
               Sha256Digest
               );
  
    if (EFI_ERROR(Status) || 
        sizeof(Sha256Digest) != TrustedCertDataSize || 
        CompareMem(Sha256Digest, TrustedCertData, TrustedCertDataSize) != 0) {
      DEBUG((DEBUG_INFO, "%a Signer Cert tbsCertificate doesn't match ContentInfo!\n", __FUNCTION__));
      return EFI_SECURITY_VIOLATION;
    }
  }

  //
  // 4. SigningCert is detached signature, Hash a serialization of the payload.
  //     Hash sequence is
  //      a. VariableName, VendorGuid, Attributes, and the Secondary Descriptor if it exists for this Type.
  //      b. Variable's new value (ie. the Data parameter's new variable content)
  //      c. If current nonce exists, and If this is an update to or deletion of a variable with type EFI_VARIABLE_AUTHENTICATION_3_NONCE, 
  //         serialize the current Variable's nonce buffer content
  //      d. If the EFI_VARIABLE_AUTHENTICATION_3.Flags field indicates the presence of a NewCert structure, serialize NewCert
  //
  //
  //     NewCertSize, OrigNonceSize could be zero
  //
  NewCertContentSize = StrLen(VariableName) * sizeof (UINT16) + sizeof (EFI_GUID) + sizeof (UINT32) + PayloadSize + NewCertSize;
  if (NewTimeStamp != NULL) {
    NewCertContentSize += sizeof(EFI_TIME);
  } else {
    //
    // Second Descriptor + Current Nonce conetents size
    //
    NewCertContentSize += sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE) + NewNonceSize + OrigNonceSize;
  }

  //
  // Here is to reuse scratch data area(at the end of volatile variable store)
  // to reduce SMRAM consumption for SMM variable driver.
  // The scratch buffer is enough to hold the serialized data and safe to use,
  // because it is only used at here to do verification temporarily first
  // and then used in UpdateVariable() for a time based auth variable set.
  //
  Status = mAuthVarLibContextIn->GetScratchBuffer (&NewCertContentSize, (VOID **) &NewCertContent);
  if (EFI_ERROR (Status)) {
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  //
  // 4.a  VariableName, VendorGuid, Attributes, and the Secondary Descriptor if it exists for this Type.
  //
  Buffer = NewCertContent;
  Length = StrLen (VariableName) * sizeof (CHAR16);
  CopyMem (Buffer, VariableName, Length);
  Buffer += Length;

  Length = sizeof (EFI_GUID);
  CopyMem (Buffer, VendorGuid, Length);
  Buffer += Length;

  Length = sizeof (UINT32);
  CopyMem (Buffer, &Attributes, Length);
  Buffer += Length;

  if (NewTimeStamp != NULL) {
    //
    // Secondary descriptor is EFI_TIME
    //
    CopyMem (Buffer, NewTimeStamp, sizeof (EFI_TIME));
    Buffer += sizeof (EFI_TIME);
  } else {
    //
    // Secondary descriptor is EFI_VARIABLE_AUTHENTICATION_3_NONCE
    //
    ZeroMem (&Auth3Nonce, sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE));
    Auth3Nonce.NonceSize = (UINT32)NewNonceSize;
    CopyMem (Buffer, &Auth3Nonce, sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE));
    CopyMem (Buffer + sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE), NewNonce, NewNonceSize);
    Buffer += sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE) + NewNonceSize;
  }

  //
  // 4.b  Variable's new value (ie. the Data parameter's new variable content)
  //        Payload could be zero. e.g. Update Cert or TimeStamp or Nonce without touching variable value
  //
  if (PayloadSize != 0) {
    CopyMem (Buffer, Payload, PayloadSize);
    Buffer += PayloadSize;
  }

  //
  // 4.c  If current nonce exists, and If this is an update to or deletion of a variable with type EFI_VARIABLE_AUTHENTICATION_3_NONCE, 
  //      serialize the current Variable's nonce buffer content
  //
  if (NewTimeStamp == NULL && OrigNonceSize != 0) {
    CopyMem (Buffer, OrigNonce, OrigNonceSize);
    Buffer += OrigNonceSize;
  }

  //
  // 4.d  If the EFI_VARIABLE_AUTHENTICATION_3.Flags field indicates the presence of a NewCert structure, serialize NewCert
  //
  if (NewCertSize != 0) {
    CopyMem (Buffer, NewCert, NewCertSize);
  }

  //
  // 5. Verify SigningCert PKCS7 SignedData
  //
  VerifyStatus = Pkcs7Verify (
                   SigData,
                   SigDataSize,
                   TopLevelCert,
                   TopLevelCertSize,
                   NewCertContent,
                   NewCertContentSize
                   );
  if (!VerifyStatus) {
    DEBUG((DEBUG_ERROR, "Pkcs7Verify for Signing failed\n"));
    Status = EFI_SECURITY_VIOLATION;
  }

EXIT:

  Pkcs7FreeSigners (TopLevelCert);
  Pkcs7FreeSigners (SignerCerts);

  return Status;

}

/**
  Process variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set

  Caution: This function may receive untrusted input.
  This function may be invoked in SMM mode, and datasize and data are external input.
  This function will do basic validation, before parse the data.
  This function will parse the authentication carefully to avoid security issues, like
  buffer overflow, integer overflow.

  @param[in]  VariableName                Name of Variable to be found.
  @param[in]  VendorGuid                  Variable vendor GUID.
  @param[in]  Data                        Data pointer.
  @param[in]  DataSize                    Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in]  Attributes                  Attribute value of the variable.
  @param[in]  AuthVarType                 Verify against PK, KEK database, private database or certificate in data payload.
  @param[out] VarDel                      Delete the variable or not.

  @retval EFI_INVALID_PARAMETER           Invalid parameter.
  @retval EFI_SECURITY_VIOLATION          The variable does NOT pass the validation
                                          check carried out by the firmware.
  @retval EFI_OUT_OF_RESOURCES            Failed to process variable due to lack
                                          of resources.
  @retval EFI_SUCCESS                     Variable pass validation successfully.

**/
EFI_STATUS
VerifyEnhancedAuthPayloadAndUpdate (
  IN     CHAR16                             *VariableName,
  IN     EFI_GUID                           *VendorGuid,
  IN     VOID                               *Data,
  IN     UINTN                              DataSize,
  IN     UINT32                             Attributes
  )
{
  EFI_STATUS                          Status;
  EFI_STATUS                          FindStatus;
  BOOLEAN                             VerifyStatus;
  AUTH_VARIABLE_INFO                  OrgVariableInfo;
  UINTN                               Offset;
  EFI_VARIABLE_AUTHENTICATION_3       *Auth3;
  UINT8                               *NewCertSignerCerts;
  UINTN                               NewCertStackSize;
  UINT8                               *NewCertTopLevelCert;
  UINTN                               NewCertTopLevelCertSize;
  EFI_VARIABLE_AUTHENTICATION_3_NONCE *NewNonce;
  UINT8                               *NewNonceData;
  UINT32                              NewNonceDataSize;
  EFI_TIME                            *NewTimeStamp;
  UINT8                               *NewCert;
  UINTN                               NewCertSize;
  UINT8                               *SigningCert;
  UINTN                               SigningCertSize;
  EFI_CERT_DATA                       *NewCertDataPtr;
  UINT8                               *TrustedCertData;
  UINT32                              TrustedCertDataSize;
  UINT8                               *TrustedNonceData;
  UINT32                              TrustedNonceDataSize;
  UINT8                               *Payload;
  UINT32                              PayloadSize;
  UINT8                               OrignalType;

  //
  // Caution!! This function do not perform sanity check on any descriptors after AUTH_3 
  //           All sanity check must be done before this function
  //

  NewCertSignerCerts   = NULL;
  NewCertTopLevelCert  = NULL;
  NewTimeStamp         = NULL;
  NewCert              = NULL;
  NewCertSize          = 0;
  TrustedCertData      = NULL;
  TrustedCertDataSize  = 0;
  TrustedNonceData     = NULL;
  TrustedNonceDataSize = 0;
  NewNonceData         = NULL;
  NewNonceDataSize     = 0;
  TrustedCertData      = NULL;
  TrustedCertDataSize  = 0;
  SigningCert          = NULL;
  SigningCertSize      = 0;
  NewCertDataPtr       = NULL;
  Auth3                = (EFI_VARIABLE_AUTHENTICATION_3 *)Data;
  Offset               = sizeof(EFI_VARIABLE_AUTHENTICATION_3);

  //
  // 1. Retrieve orginal enhanced authenticated variable & cert data
  //
  ZeroMem (&OrgVariableInfo, sizeof (OrgVariableInfo));
  FindStatus = mAuthVarLibContextIn->FindVariable (
                                       VariableName,
                                       VendorGuid,
                                       &OrgVariableInfo
                                       );
  if (!EFI_ERROR(FindStatus)) {
    Status = GetCertsFromDb (
               VariableName,
               VendorGuid,
               Attributes,
               &TrustedCertData,
               &TrustedCertDataSize,
               &TrustedNonceData,
               &TrustedNonceDataSize,
               &OrignalType
               );
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "Fail to find corresponding CertData for Variable %s GUID %g Attributes %x\n", VariableName, VendorGuid, Attributes));
      return Status;
    }

    if (Auth3->Type != OrignalType) {
      DEBUG((DEBUG_ERROR, "Auth3.Type %x doesn't match type %x in Cert Database\n", Auth3->Type, OrignalType));
      return EFI_INVALID_PARAMETER;
    }
  }


  //
  // 2. Get Timestamp/Nonce after AUTH_3
  //
  if (Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE) {
    //
    // 2.1  Check TimeStamp to prevent rollback attack
    //        Data format is
    //        EFI_VARIABLE_AUTHENTICATION_3 || EFI_TIME || [ NewCert ] || SigningCert || Data
    //
    NewTimeStamp = (EFI_TIME *)(Auth3 + 1);
    if ((NewTimeStamp->Pad1 != 0) ||
        (NewTimeStamp->Nanosecond != 0) ||
        (NewTimeStamp->TimeZone != 0) ||
        (NewTimeStamp->Daylight != 0) ||
        (NewTimeStamp->Pad2 != 0)) {
      return EFI_SECURITY_VIOLATION;
    }

    if (!EFI_ERROR(FindStatus) && 
        (Attributes & EFI_VARIABLE_APPEND_WRITE) == 0 &&
        AuthServiceInternalCompareTimeStamp (NewTimeStamp, OrgVariableInfo.TimeStamp)) {
        //
        // TimeStamp check fail, suspicious replay attack, return EFI_SECURITY_VIOLATION.
        //
        DEBUG((DEBUG_ERROR, "Auth3 TimeStamp check fails!"));
        return EFI_SECURITY_VIOLATION;
    }

    Offset += sizeof(EFI_TIME);
  } else if (Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE) {
    //
    // 2.2  Check Nonce  to prevent rollback attack
    //        Data format is
    //        EFI_VARIABLE_AUTHENTICATION_3 || EFI_VARIABLE_AUTHENTICATION_3_NONCE || [ NewCert ] || SigningCert || Data
    //        
    NewNonce         = (EFI_VARIABLE_AUTHENTICATION_3_NONCE *)(Auth3 + 1);
    NewNonceData     = (UINT8 *)NewNonce + sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE);
    NewNonceDataSize = ReadUnaligned32(&NewNonce->NonceSize);
    if (!EFI_ERROR(FindStatus) &&
        NewNonceDataSize == TrustedNonceDataSize &&
        CompareMem(NewNonceData, TrustedNonceData, NewNonceDataSize) == 0) {
      //
      // Always enforce Nonce check
      //
      DEBUG((DEBUG_ERROR, "Auth3 Nonce equals to current nonce. Nonce check fails!"));
      return EFI_INVALID_PARAMETER;
    }

    Offset += sizeof(EFI_VARIABLE_AUTHENTICATION_3_NONCE) + NewNonceDataSize;
  }


  //
  // 3. Verify [NewCert] descriptor (Type WIN_CERTIFICATE_UEFI_GUID)
  //
  if ((Auth3->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) != 0) {
    NewCert     = (UINT8 *)Data + Offset;
    NewCertSize = ReadUnaligned32((UINT32 *)(NewCert + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, Hdr) + OFFSET_OF(WIN_CERTIFICATE, dwLength)));
    Status = VerifyNewCert(
               NewCert,
               NewCertSize,
               &NewCertSignerCerts,
               &NewCertStackSize,
               &NewCertTopLevelCert,
               &NewCertTopLevelCertSize
               );
    if (EFI_ERROR (Status)) {
      goto FUNC_EXIT;
    }

    NewCertDataPtr = (EFI_CERT_DATA *)(NewCertSignerCerts + sizeof(EFI_CERT_STACK));
    Offset += NewCertSize;
  } else if (EFI_ERROR(FindStatus) || Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE) {
    //
    // If Create the variable or NONCE Auth Variable update, 
    //    NewCertSignerCerts, NewCertTopLevelCert come from SigningCert 
    //
    VerifyStatus = Pkcs7GetSigners (
                     (UINT8 *)Data + Offset + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData),
                     Auth3->MetadataSize - Offset - (UINT32) (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)),
                     &NewCertSignerCerts,
                     &NewCertStackSize,
                     &NewCertTopLevelCert,
                     &NewCertTopLevelCertSize
                     );
    if (!VerifyStatus) {
      DEBUG((DEBUG_ERROR, "Pkcs7GetSigners for NewCert failed\n"));
      Status = EFI_SECURITY_VIOLATION;
      goto FUNC_EXIT;
    }
    NewCertDataPtr = (EFI_CERT_DATA *)(NewCertSignerCerts + sizeof(EFI_CERT_STACK));
  }


  //
  // 4. Verify SigningCert descriptor (Type WIN_CERTIFICATE_UEFI_GUID)
  //     Hash a serialization of the payload. Hash sequence is 
  //      a. VariableName, VendorGuid, Attributes, and the Secondary Descriptor if it exists for this Type.
  //      b. Variable's new value (ie. the Data parameter's new variable content)
  //      c. If current nonce exists, and If this is an update to or deletion of a variable with type EFI_VARIABLE_AUTHENTICATION_3_NONCE, 
  //          serialize the current nonceVariable's new value (ie. the Data parameter's new variable content)
  //      d. If the EFI_VARIABLE_AUTHENTICATION_3.Flags field indicates the presence of a NewCert structure, serialize NewCert
  //
  Payload         = (UINT8*) Data + Auth3->MetadataSize;
  PayloadSize     = (UINT32) (DataSize - Auth3->MetadataSize);
  SigningCert     = (UINT8*) Data + Offset;
  SigningCertSize = Auth3->MetadataSize - Offset;
  Status = VerifySigningCert (
             VariableName,
             VendorGuid,
             SigningCert,
             SigningCertSize,
             TrustedCertData,
             TrustedCertDataSize,
             Attributes,
             NewTimeStamp,
             TrustedNonceData,
             TrustedNonceDataSize,
             NewNonceData,
             NewNonceDataSize,
             NewCert,
             NewCertSize,
             Payload,
             PayloadSize
             );

  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "[Enhanced Auth Variable] VerifySigningCert failed %x\n", Status));
    goto FUNC_EXIT;
  }

  //
  // 5. Update/Append Variable if it passes Pkcs7Verify
  //
  if (Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE) {
    //
    // TimeStamp type enhanced authenticated variable, update TimeStamp
    //
    if (!EFI_ERROR(FindStatus) &&
        (((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) != 0 &&
        DataSize == ((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->MetadataSize) {
       //
       // Only update timeStamp in NewCert only update case,  behavior is smilar to AppendWrite without payload
       // Note!! TimeStamp  has been check earlier in this function when AppendWrite is not set
       //    
       Status = AuthServiceInternalUpdateVariableWithTimeStamp (
                  VariableName,
                  VendorGuid,
                  Payload,
                  PayloadSize,
                  Attributes | EFI_VARIABLE_APPEND_WRITE,
                  NewTimeStamp
                  );
    } else {
      //
      // Always update Payload and Timestamp
      //
      Status = AuthServiceInternalUpdateVariableWithTimeStamp (
                  VariableName,
                  VendorGuid,
                  Payload,
                  PayloadSize,
                  Attributes,
                  NewTimeStamp
                  );
    }
  } else {
    //
    // NONCE type enhanced authenticated variable. TimeStamp is not required
    // When update Cert Only case,  do not update AuthVariable 
    //
    if (EFI_ERROR(FindStatus) ||
        (((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) == 0 ||
        DataSize > ((EFI_VARIABLE_AUTHENTICATION_3 *)Data)->MetadataSize) {
      Status = AuthServiceInternalUpdateVariable (
                 VariableName,
                 VendorGuid, 
                 Payload,
                 PayloadSize,
                 Attributes
                 );
    }
  }

  //
  // Skip  Trust Cert Databae update if variable update failed 
  //
  if (EFI_ERROR(Status)) {
    goto FUNC_EXIT;
  }

  //
  // 6.Update enhanced authenticated variable Trust Cert Database
  //
  if (EFI_ERROR(FindStatus) || 
      ((Auth3->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) != 0) ||
      ((Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE) && (DataSize > Auth3->MetadataSize)) || 
      ((Auth3->Type == EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE) && (DataSize == Auth3->MetadataSize) && ((Attributes & EFI_VARIABLE_APPEND_WRITE) != 0))) {
    //
    // Update/Insert CertData to Trust Cert Database when
    //   a. Create a enhanced auth variable
    //   b. Update certficate associated with enhanced auth variable
    //   c. Update enhanced auth variable content with Nonce Type
    //       c.1 Update variable value
    //       c.2 Refresh Nonce only with APPEND_WRITE attributes
    //
    Status = InsertCertsToDb (
               VariableName,
               VendorGuid,
               Attributes,
               NewCertDataPtr->CertDataBuffer,
               ReadUnaligned32 ((UINT32 *)&(NewCertDataPtr->CertDataLength)),
               NewCertTopLevelCert,
               NewCertTopLevelCertSize,
               NewNonceData,
               NewNonceDataSize
               );  
  } else if (!EFI_ERROR(FindStatus) &&
              Auth3->MetadataSize == DataSize &&
             (Attributes & EFI_VARIABLE_APPEND_WRITE) == 0 &&
             (Auth3->Flags & EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT) == 0){
    //
    // If the Data region is empty AND no NewCert is specified, the variable will be deleted
    //
    Status = DeleteCertsFromDb (VariableName, VendorGuid, Attributes);
  }

FUNC_EXIT:

  Pkcs7FreeSigners (NewCertSignerCerts);
  Pkcs7FreeSigners (NewCertTopLevelCert);

  return Status;
}

