{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module PendingOps
  ( withPendingOps,
    PendingOps,
    insertPendingRegistering,
    insertPendingLogin,
    getPendingRegistering,
    getPendingLogin,
  )
where

import Control.Concurrent (forkIO, threadDelay)
import qualified Control.Concurrent.STM as STM
import Control.Monad (forever)
import qualified Crypto.Fido2.Model as M
import Data.Binary (Binary (get, put))
import qualified Data.Binary as Binary
import Data.Binary.Get as Binary (getInt64le, getRemainingLazyByteString)
import Data.Binary.Put as Binary (putInt64le, putLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Int (Int64)
import Data.Map (Map)
import qualified Data.Map as Map
import System.Clock (Clock (Monotonic), TimeSpec (sec), getTime)
import System.Random.Stateful (globalStdGen, uniformByteStringM)

data ExpiringChallenge = ExpiringChallenge
  { expiredAfter :: Int64,
    randomness :: LBS.ByteString
  }
  deriving (Show, Eq, Ord)

instance Binary ExpiringChallenge where
  put ExpiringChallenge {expiredAfter, randomness} = do
    Binary.putInt64le expiredAfter
    Binary.putLazyByteString randomness
  get =
    ExpiringChallenge
      <$> Binary.getInt64le
      <*> Binary.getRemainingLazyByteString

generateExpiringChallenge :: IO ExpiringChallenge
generateExpiringChallenge = do
  -- We use a monotonic clock to expire pending operations
  -- We're only interested in second-resolution
  now <- sec <$> getTime Monotonic
  -- We only look at seconds, not nanoseconds
  -- 1 hour expiration time, no real reason
  let expiredAfter = now + 60 * 60

  -- [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
  -- In order to prevent replay attacks, the challenges MUST contain enough entropy
  -- to make guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long.
  randomness <- LBS.fromStrict <$> uniformByteStringM 16 globalStdGen

  pure $ ExpiringChallenge {..}

data PendingOp
  = Registering (M.PublicKeyCredentialOptions 'M.Create)
  | Authenticating M.UserHandle (M.PublicKeyCredentialOptions 'M.Get)
  deriving (Eq, Show)

type PendingOps = STM.TVar (Map ExpiringChallenge PendingOp)

insertPendingRegistering :: PendingOps -> (M.Challenge -> M.PublicKeyCredentialOptions 'M.Create) -> IO (M.PublicKeyCredentialOptions 'M.Create)
insertPendingRegistering pending getOptions = do
  expiringChallenge <- generateExpiringChallenge
  let challenge = M.Challenge $ LBS.toStrict $ Binary.encode expiringChallenge
      options = getOptions challenge
  STM.atomically $ STM.modifyTVar pending $ Map.insert expiringChallenge $ Registering options
  pure options

insertPendingLogin :: PendingOps -> M.UserHandle -> (M.Challenge -> M.PublicKeyCredentialOptions 'M.Get) -> IO (M.PublicKeyCredentialOptions 'M.Get)
insertPendingLogin pending user getOptions = do
  expiringChallenge <- generateExpiringChallenge
  let challenge = M.Challenge $ LBS.toStrict $ Binary.encode expiringChallenge
      options = getOptions challenge
  STM.atomically $ STM.modifyTVar pending $ Map.insert expiringChallenge $ Authenticating user options
  pure options

getPendingRegistering :: PendingOps -> M.PublicKeyCredential 'M.Create -> IO (Maybe (M.PublicKeyCredentialOptions 'M.Create))
getPendingRegistering pending cred = do
  let M.Challenge challenge = M.ccdChallenge $ M.arcClientData $ M.pkcResponse cred
      expiringChallenge = Binary.decode $ LBS.fromStrict challenge
  mpendingOp <- STM.atomically $ do
    contents <- STM.readTVar pending
    let result = Map.lookup expiringChallenge contents
    STM.writeTVar pending $ Map.delete expiringChallenge contents
    pure result
  case mpendingOp of
    Nothing -> pure Nothing
    (Just (Registering options)) -> pure $ Just options
    (Just Authenticating {}) -> pure Nothing

getPendingLogin :: PendingOps -> M.PublicKeyCredential 'M.Get -> IO (Maybe (M.UserHandle, M.PublicKeyCredentialOptions 'M.Get))
getPendingLogin pending cred = do
  let M.Challenge challenge = M.ccdChallenge $ M.argClientData $ M.pkcResponse cred
      expiringChallenge = Binary.decode $ LBS.fromStrict challenge
  mpendingOp <- STM.atomically $ do
    contents <- STM.readTVar pending
    let result = Map.lookup expiringChallenge contents
    STM.writeTVar pending $ Map.delete expiringChallenge contents
    pure result
  case mpendingOp of
    Nothing -> pure Nothing
    (Just Registering {}) -> pure Nothing
    (Just (Authenticating userHandle options)) -> return $ Just (userHandle, options)

withPendingOps :: (PendingOps -> IO a) -> IO a
withPendingOps cont = do
  pending <- STM.newTVarIO Map.empty
  -- Clean up pending operations over time to prevent leaking memory for
  -- operations that are only started but never finished
  _ <- forkIO $ forever $ expireOperations pending
  cont pending

expireOperations :: PendingOps -> IO ()
expireOperations pending = do
  now <- sec <$> getTime Monotonic
  expired <- STM.atomically $ do
    ops <- STM.readTVar pending
    let (expired, valid) = Map.spanAntitone (isExpired now) ops
    STM.writeTVar pending valid
    return expired
  putStrLn $ "Removed these expired operations: " <> show expired
  threadDelay (1000 * 1000 * 10)
  where
    isExpired :: Int64 -> ExpiringChallenge -> Bool
    isExpired now challenge = expiredAfter challenge < now
