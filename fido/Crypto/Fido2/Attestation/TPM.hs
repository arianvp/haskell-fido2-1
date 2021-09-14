-- | Implements step 1-3 of the verification procedure of chapter 8.2
module Crypto.Fido2.Attestation.TPM (verify) where

import Crypto.Fido2.Attestation.Error (Error (NoAttestedCredentialDataFound))
import Crypto.Fido2.Attestation.TPM.Statement (Stmt (Stmt, alg, sig, x5c))
import Crypto.Fido2.Protocol (AttestedCredentialData (credentialPublicKey), AuthenticatorData (AuthenticatorData, attestedCredentialData, rawData), aaguid)
import Crypto.Hash (Digest, SHA256)

-- https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
verify :: Stmt -> AuthenticatorData -> Digest SHA256 -> Either Error AttestedCredentialData
verify Stmt {alg = stmtAlg, sig = stmtSig, x5c = stmtx5c} authData@AuthenticatorData {rawData = rawAuthData} clientDataHash = undefined
