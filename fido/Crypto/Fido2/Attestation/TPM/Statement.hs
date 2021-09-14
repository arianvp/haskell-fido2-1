-- | Implements step 1-3 of the verification procedure of chapter 8.3
module Crypto.Fido2.Attestation.TPM.Statement (Stmt (Stmt, alg, sig, x5c), decode) where

import Codec.CBOR.Decoding (Decoder)
import Codec.CBOR.Term (Term (TBytes, TInt, TList, TString))
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, toAlg)
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import qualified Data.X509 as X509

-- tpmStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
data Stmt = Stmt
  { alg :: COSEAlgorithmIdentifier,
    x5c :: Maybe (X509.SignedExact X509.Certificate),
    sig :: ByteString,
    certInfo :: ByteString,
    pubArea :: ByteString
  }
  deriving (Show)

decode :: [(Term, Term)] -> Decoder s Stmt
decode xs = do
  let m = Map.fromList xs
  TInt algId <- maybe (fail "no alg") pure $ Map.lookup (TString "alg") m
  alg <- toAlg algId
  x5c <- case Map.lookup (TString "x5c") m of
    -- TODO: Can we discard the rest?
    Just (TList (TBytes certBytes : _)) ->
      either fail (pure . pure) $ X509.decodeSignedCertificate certBytes
    _ -> pure Nothing
  TBytes sig <- maybe (fail "no sig") pure $ Map.lookup (TString "sig") m
  TBytes certInfo <- maybe (fail "no certInfo") pure $ Map.lookup (TString "certInfo") m
  TBytes pubArea <- maybe (fail "no pubArea") pure $ Map.lookup (TString "pubArea") m
  pure $ Stmt alg x5c sig certInfo pubArea
