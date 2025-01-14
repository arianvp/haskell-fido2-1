{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}

module Crypto.Fido2.Operations.Assertion
  ( verifyAssertionResponse,
    AssertionError (..),
    SignatureCounterResult (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import Control.Monad (unless)
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.Operations.Common (CredentialEntry (cePublicKeyBytes, ceSignCounter, ceUserHandle), failure)
import Crypto.Fido2.PublicKey (PublicKey, decodePublicKey)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation)

data AssertionError
  = AssertionDisallowedCredential (M.PublicKeyCredential 'M.Get)
  | AssertionAuthenticatedUserHandleMismatch M.UserHandle M.UserHandle
  | AssertionCredentialUserHandleMismatch M.UserHandle M.UserHandle
  | AssertionCannotVerifyUserHandle
  | AssertionChallengeMismatch M.Challenge M.Challenge
  | AssertionOriginMismatch M.Origin M.Origin
  | AssertionRpIdHashMismatch M.RpIdHash M.RpIdHash
  | AssertionUserNotPresent
  | AssertionUserNotVerified
  | AssertionInvalidSignature (Either CBOR.DeserialiseFailure (PublicKey, BS.ByteString, M.AssertionSignature))
  | AssertionPolicyRejected
  deriving (Show)

data SignatureCounterResult
  = -- | There is no signature counter being used, the database entry doesn't
    -- need to be updated
    SignatureCounterZero
  | -- | The signature counter needs to be updated in the database
    SignatureCounterUpdated M.SignatureCounter
  | -- | The signature counter decreased, the authenticator was potentially
    -- cloned
    SignatureCounterPotentiallyCloned
  deriving (Show)

verifyAssertionResponse ::
  -- | The origin of the server
  M.Origin ->
  -- | The hash of the relying party id
  M.RpIdHash ->
  -- | The user handle, in case the user is authenticated already
  Maybe M.UserHandle ->
  -- | The database entry for the credential, as created in the initial
  -- attestation and optionally updated in subsequent assertions
  CredentialEntry ->
  -- | The options that were passed to the get() method
  M.PublicKeyCredentialOptions 'M.Get ->
  -- | The credential returned from get()
  M.PublicKeyCredential 'M.Get ->
  -- | Either a non-empty list of validation errors in case of the assertion
  -- being invalid
  -- Or in case of success a signature counter result, which should be dealt
  -- with
  Validation (NonEmpty AssertionError) SignatureCounterResult
verifyAssertionResponse origin rpIdHash mauthenticatedUser entry options credential = do
  -- 1. Let options be a new PublicKeyCredentialRequestOptions structure
  -- configured to the Relying Party's needs for the ceremony.
  -- NOTE: Implemented by caller
  -- If options.allowCredentials is present, the transports member of each
  -- item SHOULD be set to the value returned by
  -- credential.response.getTransports() when the corresponding credential was
  -- registered.
  -- TODO

  -- 2. Call navigator.credentials.get() and pass options as the publicKey
  -- option. Let credential be the result of the successfully resolved promise.
  -- If the promise is rejected, abort the ceremony with a user-visible error,
  -- or otherwise guide the user experience as might be determinable from the
  -- context available in the rejected promise. For information on different
  -- error contexts and the circumstances leading to them, see § 6.3.3 The
  -- authenticatorGetAssertion Operation.
  -- NOTE: Implemented by caller

  -- 3. Let response be credential.response. If response is not an instance of
  -- AuthenticatorAssertionResponse, abort the ceremony with a user-visible
  -- error.
  -- NOTE: Already done as part of decoding
  let response = M.pkcResponse credential

  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
  -- TODO: Implement extensions

  -- 5. If options.allowCredentials is not empty, verify that credential.id
  -- identifies one of the public key credentials listed in
  -- options.allowCredentials.
  let allowCredentials = M.pkcogAllowCredentials options
  unless (null allowCredentials || M.pkcIdentifier credential `elem` map M.pkcdId allowCredentials) . failure $ AssertionDisallowedCredential credential

  -- 6. Identify the user being authenticated and verify that this user is the
  -- owner of the public key credential source credentialSource identified by
  -- credential.id:
  --
  -- -> If the user was identified before the authentication ceremony was
  -- initiated, e.g., via a username or cookie, verify that the identified
  -- user is the owner of credentialSource. If response.userHandle is present,
  -- let userHandle be its value. Verify that userHandle also maps to the same
  -- user.
  --
  -- -> If the user was not identified before the authentication ceremony was
  -- initiated, verify that response.userHandle is present, and that the user
  -- identified by this value is the owner of credentialSource.
  let owner = ceUserHandle entry
  case (mauthenticatedUser, M.argUserHandle response) of
    (Just authenticatedUser, Just userHandle)
      | authenticatedUser /= owner ->
        failure $ AssertionAuthenticatedUserHandleMismatch authenticatedUser owner
      | userHandle /= owner ->
        failure $ AssertionCredentialUserHandleMismatch userHandle owner
      | otherwise -> pure ()
    (Just authenticatedUser, Nothing)
      | authenticatedUser /= owner ->
        failure $ AssertionAuthenticatedUserHandleMismatch authenticatedUser owner
      | otherwise -> pure ()
    (Nothing, Just userHandle)
      | userHandle /= owner ->
        failure $ AssertionCredentialUserHandleMismatch userHandle owner
      | otherwise -> pure ()
    (Nothing, Nothing) ->
      failure AssertionCannotVerifyUserHandle

  -- 7. Using credential.id (or credential.rawId, if base64url encoding is
  -- inappropriate for your use case), look up the corresponding credential
  -- public key and let credentialPublicKey be that credential public key.
  -- NOTE: Done by the caller, passed with entry

  -- 8. Let cData, authData and sig denote the value of response’s
  -- clientDataJSON, authenticatorData, and signature respectively.
  let M.AuthenticatorAssertionResponse
        { M.argClientData = c,
          M.argAuthenticatorData = authData,
          M.argSignature = sig
        } = response

  -- 9. Let JSONtext be the result of running UTF-8 decode on the value of
  -- cData.
  -- NOTE: Done as part of decoding

  -- 10. Let C, the client data claimed as used for the signature, be the
  -- result of running an implementation-specific JSON parser on JSONtext.
  -- NOTE: Done as part of decoding

  -- 11. Verify that the value of C.type is the string webauthn.get.
  -- NOTE: Done as part of decoding

  -- 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  unless (M.ccdChallenge c == M.pkcogChallenge options) $
    failure $ AssertionChallengeMismatch (M.ccdChallenge c) (M.pkcogChallenge options)

  -- 13. Verify that the value of C.origin matches the Relying Party's origin.
  unless (M.ccdOrigin c == origin) $
    failure $ AssertionOriginMismatch (M.ccdOrigin c) origin

  -- 14. Verify that the value of C.tokenBinding.status matches the state of
  -- Token Binding for the TLS connection over which the attestation was
  -- obtained. If Token Binding was used on that TLS connection, also verify
  -- that C.tokenBinding.id matches the base64url encoding of the Token
  -- Binding ID for the connection.
  -- TODO

  -- 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
  -- expected by the Relying Party.
  -- Note: If using the appid extension, this step needs some special logic.
  -- See § 10.1 FIDO AppID Extension (appid) for details.
  unless (M.adRpIdHash authData == rpIdHash) $
    failure $ AssertionRpIdHashMismatch (M.adRpIdHash authData) rpIdHash

  -- 16. Verify that the User Present bit of the flags in authData is set.
  unless (M.adfUserPresent (M.adFlags authData)) $
    failure AssertionUserNotPresent

  -- 17. If user verification is required for this assertion, verify that the
  -- User Verified bit of the flags in authData is set.
  -- NOTE: The spec is interpreted to mean that the userVerification option
  -- being set to "required" is what is meant by whether user verification is
  -- required
  case ( M.pkcogUserVerification options,
         M.adfUserVerified (M.adFlags authData)
       ) of
    (M.UserVerificationRequirementRequired, True) -> pure ()
    (M.UserVerificationRequirementRequired, False) -> failure AssertionUserNotVerified
    (M.UserVerificationRequirementPreferred, True) -> pure ()
    -- TODO: Maybe throw warning that user verification was preferred but not provided
    (M.UserVerificationRequirementPreferred, False) -> pure ()
    -- TODO: Maybe throw warning that user verification was discouraged but provided
    (M.UserVerificationRequirementDiscouraged, True) -> pure ()
    (M.UserVerificationRequirementDiscouraged, False) -> pure ()

  -- 18. Verify that the values of the client extension outputs in
  -- clientExtensionResults and the authenticator extension outputs in the
  -- extensions in authData are as expected, considering the client extension
  -- input values that were given in options.extensions and any specific policy
  -- of the Relying Party regarding unsolicited extensions, i.e., those that
  -- were not specified as part of options.extensions. In the general case,
  -- the meaning of "are as expected" is specific to the Relying Party and
  -- which extensions are in use.
  -- TODO

  -- 19. Let hash be the result of computing a hash over the cData using SHA-256.
  -- NOTE: Done during decoding, since it relies on the specific serialization
  -- used
  let hash = convert (M.unClientDataHash (M.ccdHash c))

  -- 20. Using credentialPublicKey, verify that sig is a valid signature over
  -- the binary concatenation of authData and hash.
  let pubKeyBytes = cePublicKeyBytes entry
      message = M.adRawData authData <> hash
  case CBOR.deserialiseFromBytes decodePublicKey (LBS.fromStrict (M.unPublicKeyBytes pubKeyBytes)) of
    Left err -> failure $ AssertionInvalidSignature (Left err)
    Right (_, pubKey) ->
      unless (PublicKey.verify pubKey message (M.unAssertionSignature sig)) $
        failure $ AssertionInvalidSignature $ Right (pubKey, message, sig)

  -- 21. Let storedSignCount be the stored signature counter value associated
  -- with credential.id. If authData.signCount is nonzero or storedSignCount
  -- is nonzero, then run the following sub-step:
  -- - If authData.signCount is
  --   -> greater than storedSignCount:
  --      Update storedSignCount to be the value of authData.signCount.
  --   -> less than or equal to storedSignCount:
  --      This is a signal that the authenticator may be cloned, i.e. at least
  --      two copies of the credential private key may exist and are being
  --      used in parallel. Relying Parties should incorporate this information
  --      into their risk scoring. Whether the Relying Party updates
  --      storedSignCount in this case, or not, or fails the authentication
  --      ceremony or not, is Relying Party-specific.
  signCountResult <- case (M.adSignCount authData, ceSignCounter entry) of
    (0, 0) -> pure SignatureCounterZero
    (returned, stored)
      | returned > stored -> pure $ SignatureCounterUpdated returned
      | otherwise -> pure SignatureCounterPotentiallyCloned

  -- 22. If all the above steps are successful, continue with the
  -- authentication ceremony as appropriate. Otherwise, fail the
  -- authentication ceremony.
  pure signCountResult
