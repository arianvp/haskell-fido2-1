{-# LANGUAGE CPP #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Fido2.FFI
  ( FIDOOption(..),
    omit,
    false,
    true,
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
