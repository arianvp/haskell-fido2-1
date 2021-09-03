{-# LANGUAGE CPP #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Fido2.Assertion.FFI () where

import Data.Word (Word32, Word8)
import Foreign (Ptr)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (CInt), CSize (CSize))

#include <fido.h>

data AssertStruct

type AssertHandle = Ptr AssertStruct

foreign import ccall "fido_assert_new"
  c_fido_assert_new :: IO AssertHandle

-- TODO: Use in Finalizer
foreign import ccall "fido_assert_free"
  c_fido_assert_free :: Ptr AssertHandle -> IO ()

foreign import ccall "fido_assert_count"
  c_fido_assert_count :: AssertHandle -> CSize

foreign import ccall "fido_assert_rp_id"
  c_fido_assert_rp_id :: AssertHandle -> CString

foreign import ccall "fido_assert_user_display_name"
  c_fido_assert_user_display_name :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_user_icon"
  c_fido_assert_user_icon :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_user_name"
  c_fido_assert_user_name :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_authdata_ptr"
  c_fido_assert_authdata_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_client_data_hash_ptr"
  c_fido_assert_client_data_hash_ptr :: AssertHandle -> CString

foreign import ccall "fido_assert_blob_ptr"
  c_fido_assert_blob_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_hmac_secret_ptr"
  c_fido_assert_hmac_secret_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_largeblob_key_ptr"
  c_fido_assert_largeblob_key_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_user_sig_ptr"
  c_fido_assert_user_sig_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_user_id_ptr"
  c_fido_assert_user_id_ptr :: AssertHandle -> CSize -> CString

foreign import ccall "fido_assert_authdata_len"
  c_fido_assert_authdata_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_clientdata_hash_len"
  c_fido_assert_clientdata_hash_len :: AssertHandle -> CSize

foreign import ccall "fido_assert_blob_len"
  c_fido_assert_blob_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_hmac_secret_len"
  c_fido_assert_hmac_secret_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_largeblob_key_len"
  c_fido_assert_largeblob_key_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_user_id_len"
  c_fido_assert_user_id_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_sig_len"
  c_fido_assert_sig_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_id_len"
  c_fido_assert_id_len :: AssertHandle -> CSize -> CSize

foreign import ccall "fido_assert_sigcount"
  c_fido_assert_sigcount :: AssertHandle -> CSize -> Word32

foreign import ccall "fido_assert_flags"
  c_fido_assert_flags :: AssertHandle -> CSize -> Word8

{- SETTERS -}

foreign import ccall "fido_assert_set_authdata"
  c_fido_assert_set_authdata :: AssertHandle -> CSize -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_authdata_raw"
  c_fido_assert_set_authdata_raw :: AssertHandle -> CSize -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_clientdata"
  c_fido_assert_set_clientdata :: AssertHandle -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_clientdata_hash"
  c_fido_assert_set_clientdata_hash :: AssertHandle -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_count"
  c_fido_assert_set_count :: AssertHandle -> CSize -> CInt

foreign import ccall "fido_assert_set_extensions"
  c_fido_assert_set_extensions :: AssertHandle -> CInt -> CInt

foreign import ccall "fido_assert_set_hmac_salt"
  c_fido_assert_set_hmac_salt :: AssertHandle -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_hmac_secret"
  c_fido_assert_set_hmac_secret :: AssertHandle -> CString -> CSize -> CInt

foreign import ccall "fido_assert_set_up"
  c_fido_assert_set_up :: AssertHandle -> FIDOOption -> CInt

foreign import ccall "fido_assert_set_uv"
  c_fido_assert_set_uv :: AssertHandle -> FIDOOption -> CInt

foreign import ccall "fido_assert_set_rp"
  c_fido_assert_set_rp :: AssertHandle -> CString -> CInt

foreign import ccall "fido_assert_set_sig"
  c_fido_assert_set_sig :: AssertHandle -> CSize -> CString -> CSize  -> CInt

-- TODO: Pointer should be to a pk
foreign import ccall "fido_assert_verify"
  c_fido_assert_verify :: AssertHandle -> CSize -> CInt -> Ptr pk -> CInt
