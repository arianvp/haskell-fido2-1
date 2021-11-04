{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Operations.Attestation.Apple
  ( format,
    Format (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM)
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (certPublicKey)
import Crypto.Hash (Digest, SHA256)
import qualified Data.ASN1.Parse as ASN1
import Data.Bifunctor (first)
import Data.HashMap.Strict (HashMap, (!?))
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Void (Void)
import qualified Data.X509 as X509
import Debug.Trace (trace)

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

data DecodingError
  = DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | DecodingErrorCertificate String
  | DecodingErrorPublicKey X509.PubKey
  deriving (Show, Exception)

newtype AppleNonceExtension = AppleNonceExtension
  { nonce :: Digest SHA256
  }
  deriving (Eq, Show)

instance X509.Extension AppleNonceExtension where
  extOID = const [1, 2, 840, 113635, 100, 8, 2]
  extHasNestedASN1 = const False
  extEncode = error "extEncode for AppleNonceExtension is unimplemented"
  extDecode asn1 = trace (show asn1) $ ASN1.runParseASN1 decode asn1
    where
      decode :: ASN1.ParseASN1 AppleNonceExtension
      decode = undefined

instance M.AttestationStatementFormat Format where
  type AttStmt Format = ()
  asfIdentifier _ = "apple"

  type AttStmtDecodingError Format = DecodingError
  asfDecode _ xs = case xs !? "x5c" of
    Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)) -> do
      x5c@(credCert :| _) <- forM x5cRaw $ \case
        CBOR.TBytes certBytes ->
          first DecodingErrorCertificate (X509.decodeSignedCertificate certBytes)
        _ ->
          Left (DecodingErrorUnexpectedCBORStructure xs)

      let cert = X509.getCertificate credCert

      pubKey <- case certPublicKey cert of
        Nothing -> Left $ DecodingErrorPublicKey (X509.certPubKey cert)
        Just key -> pure key
      undefined
    _ -> Left (DecodingErrorUnexpectedCBORStructure xs)

  type AttStmtVerificationError Format = Void
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
