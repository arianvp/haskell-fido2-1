{-# LANGUAGE CPP #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Fido2.Credential.FFI
  ( FIDOOption,
    omit,
    false,
    true,
    c_fido_cred_new,
    c_fido_cred_free,
    c_fido_cred_prot,
    c_fido_cred_fmt,
    c_fido_cred_rp_id,
    c_fido_cred_rp_name,
    c_fido_cred_rp_user_name,
    c_fido_cred_set_authdata,
    c_fido_cred_set_authdata_raw,
    c_fido_cred_set_x509,
    c_fido_cred_set_sig,
    c_fido_cred_set_id,
    c_fido_cred_set_clientdata,
    c_fido_cred_set_clientdata_hash,
    c_fido_cred_set_rp,
    c_fido_cred_set_user,
    c_fido_cred_set_extensions,
    c_fido_cred_set_blob,
    c_fido_cred_set_prot,
    c_fido_cred_set_rk,
    c_fido_cred_set_uv,
    c_fido_cred_set_fmt,
    c_fido_cred_set_type,
  )
where

import Foreign (Ptr)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (CInt), CSize (CSize))

#include <fido.h>

#{enum FIDOOption, FIDOOption
 , omit = FIDO_OPT_OMIT
 , false = FIDO_OPT_FALSE
 , true = FIDO_OPT_TRUE
 }

newtype FIDOOption = FIDOOption {unFIDOOption :: CInt}
  deriving (Eq, Ord, Show, Read)

data CredentialStruct

type CredentialHandle = Ptr CredentialStruct

foreign import ccall "fido_cred_new"
  c_fido_cred_new :: IO CredentialHandle

-- TODO: Use in Finalizer
foreign import ccall "fido_cred_free"
  c_fido_cred_free :: Ptr CredentialHandle -> IO ()

-- TODO: Wrap (The Int is just a status indication, we should result in IO CredentialHandle)
foreign import ccall "fido_cred_prot"
  c_fido_cred_prot :: CredentialHandle -> IO CInt

-- TODO: Wrap (Should probably result in Bytestring or String)
foreign import ccall "fido_cred_fmt"
  c_fido_cred_fmt :: CredentialHandle -> CString

-- TODO: Wrap (Should probably result in Bytestring or String)
foreign import ccall "fido_cred_rp_id"
  c_fido_cred_rp_id :: CredentialHandle -> CString

-- TODO: Wrap (Should probably result in Bytestring or String)
foreign import ccall "fido_cred_rp_name"
  c_fido_cred_rp_name :: CredentialHandle -> CString

-- TODO: Wrap (Should probably result in Bytestring or String)
foreign import ccall "fido_cred_rp_user_name"
  c_fido_cred_rp_user_name :: CredentialHandle -> CString

foreign import ccall "fido_cred_set_authdata"
  c_fido_cred_set_authdata :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_authdata_raw"
  c_fido_cred_set_authdata_raw :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_x509"
  c_fido_cred_set_x509 :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_sig"
  c_fido_cred_set_sig :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_id"
  c_fido_cred_set_id :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_clientdata"
  c_fido_cred_set_clientdata :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_clientdata_hash"
  c_fido_cred_set_clientdata_hash :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_rp"
  c_fido_cred_set_rp :: CredentialHandle -> CString -> CString -> IO CInt

foreign import ccall "fido_cred_set_user"
  c_fido_cred_set_user :: CredentialHandle -> CString -> CSize -> CString -> CString -> CString -> IO CInt

foreign import ccall "fido_cred_set_extensions"
  c_fido_cred_set_extensions :: CredentialHandle -> CInt -> IO CInt

foreign import ccall "fido_cred_set_blob"
  c_fido_cred_set_blob :: CredentialHandle -> CString -> CSize -> IO CInt

foreign import ccall "fido_cred_set_prot"
  c_fido_cred_set_prot :: CredentialHandle -> CInt -> IO CInt

foreign import ccall "fido_cred_set_rk"
  c_fido_cred_set_rk :: CredentialHandle -> FIDOOption -> IO CInt

foreign import ccall "fido_cred_set_uv"
  c_fido_cred_set_uv :: CredentialHandle -> FIDOOption -> IO CInt

foreign import ccall "fido_cred_set_fmt"
  c_fido_cred_set_fmt :: CredentialHandle -> CInt -> IO CInt

foreign import ccall "fido_cred_set_type"
  c_fido_cred_set_type :: CredentialHandle -> CInt -> IO CInt
