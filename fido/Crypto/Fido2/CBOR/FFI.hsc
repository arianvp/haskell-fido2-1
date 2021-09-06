{-# LANGUAGE CPP #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Fido2.CBOR.FFI
  ( c_fido_cbor_info_new,
    c_fido_cbor_info_free,
    c_fido_cbor_info_aaguid_ptr,
    c_fido_cbor_info_extensions_ptr,
    c_fido_cbor_info_protocols_ptr,
    c_fido_cbor_info_transports_ptr,
    c_fido_cbor_info_versions_ptr,
    c_fido_cbor_info_options_name_ptr,
    c_fido_cbor_info_options_value_ptr,
    c_fido_cbor_info_algorithm_type,
    c_fido_cbor_info_algorithm_cose,
    c_fido_cbor_info_algorithm_count,
    c_fido_cbor_info_aaguid_len,
    c_fido_cbor_info_extensions_len,
    c_fido_cbor_info_protocols_len,
    c_fido_cbor_info_transports_len,
    c_fido_cbor_info_versions_len,
    c_fido_cbor_info_options_len,
    c_fido_cbor_info_maxmsgsiz,
    c_fido_cbor_info_maxcredbloblen,
    c_fido_cbor_info_maxcredcntlst,
    c_fido_cbor_info_maxcredidlen,
    c_fido_cbor_info_fwversion,
  )
where

import Foreign (Ptr)
import Data.Word (Word64, Word8)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (CInt), CSize (CSize))

#include <fido.h>

data CBORStruct

type CBORHandle = Ptr CBORStruct

foreign import ccall "fido_cbor_info_new"
  c_fido_cbor_info_new :: IO CBORHandle

foreign import ccall "fido_cbor_info_free"
  c_fido_cbor_info_free :: Ptr CBORHandle -> IO ()

foreign import ccall "fido_cbor_info_aaguid_ptr"
  c_fido_cbor_info_aaguid_ptr :: CBORHandle -> CString

foreign import ccall "fido_cbor_info_extensions_ptr"
  c_fido_cbor_info_extensions_ptr :: CBORHandle -> Ptr CString

foreign import ccall "fido_cbor_info_protocols_ptr"
  c_fido_cbor_info_protocols_ptr :: CBORHandle -> Ptr Word8

foreign import ccall "fido_cbor_info_transports_ptr"
  c_fido_cbor_info_transports_ptr :: CBORHandle -> Ptr CString

foreign import ccall "fido_cbor_info_versions_ptr"
  c_fido_cbor_info_versions_ptr :: CBORHandle -> Ptr CString

foreign import ccall "fido_cbor_info_options_name_ptr"
  c_fido_cbor_info_options_name_ptr :: CBORHandle -> Ptr CString

foreign import ccall "fido_cbor_info_options_value_ptr"
  c_fido_cbor_info_options_value_ptr :: CBORHandle -> Ptr Bool

foreign import ccall "fido_cbor_info_algorithm_type"
  c_fido_cbor_info_algorithm_type :: CBORHandle -> CSize -> CString

foreign import ccall "fido_cbor_info_algorithm_cose"
  c_fido_cbor_info_algorithm_cose :: CBORHandle -> CSize -> CInt

foreign import ccall "fido_cbor_info_algorithm_count"
  c_fido_cbor_info_algorithm_count :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_aaguid_len"
  c_fido_cbor_info_aaguid_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_extensions_len"
  c_fido_cbor_info_extensions_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_protocols_len"
  c_fido_cbor_info_protocols_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_transports_len"
  c_fido_cbor_info_transports_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_versions_len"
  c_fido_cbor_info_versions_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_options_len"
  c_fido_cbor_info_options_len :: CBORHandle -> CSize

foreign import ccall "fido_cbor_info_maxmsgsiz"
  c_fido_cbor_info_maxmsgsiz :: CBORHandle -> Word64

foreign import ccall "fido_cbor_info_maxcredbloblen"
  c_fido_cbor_info_maxcredbloblen :: CBORHandle -> Word64

foreign import ccall "fido_cbor_info_maxcredcntlst"
  c_fido_cbor_info_maxcredcntlst :: CBORHandle -> Word64

foreign import ccall "fido_cbor_info_maxcredidlen"
  c_fido_cbor_info_maxcredidlen :: CBORHandle -> Word64

foreign import ccall "fido_cbor_info_fwversion"
  c_fido_cbor_info_fwversion :: CBORHandle -> Word64
