{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ViewPatterns #-}

module Main
  ( main,
  )
where

import Control.Concurrent.STM (TVar)
import qualified Control.Concurrent.STM as STM
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT, runMaybeT))
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding (decodeCreatedPublicKeyCredential, decodeRequestedPublicKeyCredential)
import Crypto.Fido2.Model.JavaScript.Encoding (encodePublicKeyCredentialCreationOptions, encodePublicKeyCredentialRequestOptions)
import Crypto.Fido2.Operations.Assertion (verifyAssertionResponse)
import Crypto.Fido2.Operations.Attestation (AttestationError, allSupportedFormats, verifyAttestationResponse)
import Crypto.Fido2.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId))
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier (COSEAlgorithmIdentifierES256))
import Crypto.Hash (hash)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LBS
import Data.List (find)
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.IO as Text
import qualified Data.Text.Lazy as LText
import qualified Data.Text.Lazy.Encoding as LText
import Data.Validation (Validation (Failure, Success))
import qualified Database
import GHC.Generics (Generic)
import qualified Network.HTTP.Types as HTTP
import Network.Wai.Middleware.Static (addBase, staticPolicy)
import System.Environment (getArgs)
import System.Random.Stateful (globalStdGen, uniformM)
import qualified Web.Cookie as Cookie
import Web.Scotty (ScottyM)
import qualified Web.Scotty as Scotty

data PendingOp
  = Registering (M.PublicKeyCredentialOptions 'M.Create)
  | Authenticating M.UserHandle (M.PublicKeyCredentialOptions 'M.Get)
  deriving (Eq, Show)

type PendingOps = TVar (Map M.Challenge PendingOp)

data RegisterBeginReq = RegisterBeginReq
  { userName :: Text,
    displayName :: Text
  }
  deriving (Show, FromJSON)
  deriving stock (Generic)

setAuthenticatedAs :: Database.Connection -> M.UserHandle -> Scotty.ActionM ()
setAuthenticatedAs db userHandle = do
  token <- liftIO $ uniformM globalStdGen
  liftIO $
    Database.withTransaction db $ \tx ->
      Database.insertAuthToken tx token userHandle
  let setCookie =
        Cookie.defaultSetCookie
          { Cookie.setCookieName = "auth-token",
            Cookie.setCookieValue = Base64.encodeUnpadded (Database.unAuthToken token),
            Cookie.setCookieSameSite = Just Cookie.sameSiteStrict,
            Cookie.setCookieHttpOnly = True,
            Cookie.setCookiePath = Just "/",
            Cookie.setCookieSecure = True
          }
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))

getAuthenticatedUser :: Database.Connection -> Scotty.ActionM (Maybe M.UserHandle)
getAuthenticatedUser db = runMaybeT $ do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "auth-token" cookies
  token <- MaybeT . pure $ either (const Nothing) (Just . Database.AuthToken) $ Base64.decodeUnpadded sessionCookie
  MaybeT $
    liftIO $
      Database.withTransaction db $ \tx ->
        Database.getAuthTokenUser tx token

app :: M.Origin -> M.RpIdHash -> Database.Connection -> PendingOps -> ScottyM ()
app origin rpIdHash db pending = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.post "/register/begin" $ beginRegistration db pending
  Scotty.post "/register/complete" $ completeRegistration origin rpIdHash db pending
  Scotty.post "/login/begin" $ beginLogin db pending
  Scotty.post "/login/complete" $ completeLogin origin rpIdHash db pending
  Scotty.get "/requires-auth" $ do
    getAuthenticatedUser db >>= \case
      Nothing -> Scotty.raiseStatus HTTP.status401 "Please authenticate first"
      Just user -> Scotty.json @Text $ "This should only be visible when authenticated as user: " <> Text.decodeUtf8 (Base64.encodeUnpadded (M.unUserHandle user))

mkCredentialDescriptor :: CredentialEntry -> M.PublicKeyCredentialDescriptor
mkCredentialDescriptor CredentialEntry {ceCredentialId} =
  M.PublicKeyCredentialDescriptor
    { M.pkcdTyp = M.PublicKeyCredentialTypePublicKey,
      M.pkcdId = ceCredentialId,
      M.pkcdTransports = Nothing
    }

data RegistrationResult
  = RegistrationSuccess
  | AlreadyRegistered
  | AttestationError AttestationError
  deriving (Show)

handleError :: Show e => Either e a -> Scotty.ActionM a
handleError (Left x) = Scotty.raiseStatus HTTP.status400 . LText.fromStrict . Text.pack . show $ x
handleError (Right x) = pure x

beginLogin :: Database.Connection -> PendingOps -> Scotty.ActionM ()
beginLogin db pending = do
  userId' <- Scotty.jsonData @Text
  userId <- case Base64.decodeUnpadded (Text.encodeUtf8 userId') of
    Left err -> fail $ "Failed to base64url decode the user id " <> show userId' <> ": " <> err
    Right res -> pure $ M.UserHandle res
  credentials <- liftIO $
    Database.withTransaction db $ \tx -> do
      Database.getCredentialsByUserId tx userId
  when (null credentials) $ Scotty.raiseStatus HTTP.status404 "User not found"
  challenge <- liftIO $ uniformM globalStdGen
  let options =
        M.PublicKeyCredentialRequestOptions
          { M.pkcogRpId = Nothing,
            M.pkcogTimeout = Nothing,
            M.pkcogChallenge = challenge,
            M.pkcogAllowCredentials = map mkCredentialDescriptor credentials,
            M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
            M.pkcogExtensions = Nothing
          }
  liftIO $ STM.atomically $ STM.modifyTVar pending $ Map.insert challenge $ Authenticating userId options
  Scotty.json $ encodePublicKeyCredentialRequestOptions options

completeLogin :: M.Origin -> M.RpIdHash -> Database.Connection -> PendingOps -> Scotty.ActionM ()
completeLogin origin rpIdHash db pending = do
  credential <- Scotty.jsonData @JS.RequestedPublicKeyCredential

  cred <- case decodeRequestedPublicKeyCredential credential of
    Left err -> fail $ show err
    Right result -> pure result

  let challenge = M.ccdChallenge $ M.argClientData $ M.pkcResponse cred

  mpendingOp <- liftIO $
    STM.atomically $ do
      contents <- STM.readTVar pending
      let result = Map.lookup challenge contents
      STM.writeTVar pending $ Map.delete challenge contents
      pure result

  (userHandle, options) <- case mpendingOp of
    Nothing -> Scotty.raiseStatus HTTP.status401 "Challenge not known"
    (Just (Registering _)) -> Scotty.raiseStatus HTTP.status401 "Wrong operation"
    (Just (Authenticating userHandle options)) -> return (userHandle, options)

  -- TODO: Query for the credential id directly
  entries <- liftIO $
    Database.withTransaction db $ \tx -> Database.getCredentialsByUserId tx userHandle
  entry <- case find ((== M.pkcIdentifier cred) . ceCredentialId) entries of
    Nothing -> fail "Credential not found"
    Just entry -> pure entry

  -- step 1 to 17
  -- We abort if we couldn't attest the credential
  -- FIXME
  _newSigCount <- case verifyAssertionResponse origin rpIdHash Nothing entry options cred of
    Failure (err :| _) -> fail $ show err
    Success result -> pure result
  -- FIXME: Set new signature count
  setAuthenticatedAs db userHandle
  Scotty.json @Text "Welcome."

beginRegistration :: Database.Connection -> PendingOps -> Scotty.ActionM ()
beginRegistration db pending = do
  req@RegisterBeginReq {userName, displayName} <- Scotty.jsonData @RegisterBeginReq
  liftIO $ putStrLn $ "/register/begin, received " <> show req
  challenge <- liftIO $ uniformM globalStdGen
  userId <- liftIO $ uniformM globalStdGen
  let user =
        M.PublicKeyCredentialUserEntity
          { M.pkcueId = userId,
            M.pkcueDisplayName = M.UserAccountDisplayName displayName,
            M.pkcueName = M.UserAccountName userName
          }
  let options = defaultPkcco user challenge
  liftIO $ putStrLn $ "/register/begin, sending " <> show options
  Scotty.json $ encodePublicKeyCredentialCreationOptions options
  liftIO $ STM.atomically $ STM.modifyTVar pending $ Map.insert challenge $ Registering options
  liftIO $
    Database.withTransaction db $ \tx -> do
      Database.addUser tx user

completeRegistration :: M.Origin -> M.RpIdHash -> Database.Connection -> PendingOps -> Scotty.ActionM ()
completeRegistration origin rpIdHash db pending = do
  credential <- Scotty.jsonData @JS.CreatedPublicKeyCredential
  cred <- case decodeCreatedPublicKeyCredential allSupportedFormats credential of
    Left err -> fail $ show err
    Right result -> pure result
  liftIO $ putStrLn $ "/register/complete, received " <> show cred

  let challenge = M.ccdChallenge $ M.arcClientData $ M.pkcResponse cred

  mpendingOp <- liftIO $
    STM.atomically $ do
      contents <- STM.readTVar pending
      let result = Map.lookup challenge contents
      STM.writeTVar pending $ Map.delete challenge contents
      pure result

  options <- case mpendingOp of
    Nothing -> Scotty.raiseStatus HTTP.status401 "Challenge not known"
    (Just (Registering options)) -> return options
    (Just (Authenticating _ _)) -> Scotty.raiseStatus HTTP.status401 "Wrong operation"

  let userHandle = M.pkcueId $ M.pkcocUser options
  -- step 1 to 17
  -- We abort if we couldn't attest the credential
  -- FIXME
  entry <- case verifyAttestationResponse origin rpIdHash options cred of
    Failure (err :| _) -> fail $ show err
    Success result -> pure result
  -- if the credential was succesfully attested, we will see if the
  -- credential doesn't exist yet, and if it doesn't, insert it.
  result <- liftIO $
    Database.withTransaction db $ \tx -> do
      -- If a credential with this id existed already, it must belong to the
      -- current user, otherwise it's an error. The spec allows removing the
      -- credential from the old user instead, but we don't do that.
      existingUserId <- Database.getUserByCredentialId tx (ceCredentialId entry)
      case existingUserId of
        Nothing -> do
          Database.addAttestedCredentialData tx entry
          pure $ Right ()
        Just existingUserId | userHandle == existingUserId -> pure $ Right ()
        Just _differentUserId -> pure $ Left AlreadyRegistered
  handleError result
  setAuthenticatedAs db userHandle

defaultPkcco :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcco userEntity challenge =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp = M.PublicKeyCredentialRpEntity {M.pkcreId = Nothing, M.pkcreName = "ACME"},
      M.pkcocUser = userEntity,
      M.pkcocChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = COSEAlgorithmIdentifierES256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = [],
      M.pkcocAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = M.UserVerificationRequirementPreferred
            },
      M.pkcocAttestation = M.AttestationConveyancePreferenceDirect,
      M.pkcocExtensions = Nothing
    }

main :: IO ()
main = do
  [Text.pack -> origin, Text.pack -> domain, read -> port] <- getArgs
  db <- Database.connect
  Database.initialize db
  pending <- STM.newTVarIO Map.empty
  Text.putStrLn $ "You can view the web-app at: " <> origin <> "/index.html"
  let rpIdHash = M.RpIdHash $ hash $ Text.encodeUtf8 domain
  Scotty.scotty port $ app (M.Origin origin) rpIdHash db pending
