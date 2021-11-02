{-# LANGUAGE ScopedTypeVariables #-}

module Session (getSessionScotty, casSession, IsSession (..), SessionId) where

import qualified Control.Concurrent.STM as STM
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT, runMaybeT))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LBS
import Data.Map (Map)
import qualified Data.Map as Map
import qualified Data.Text.Lazy.Encoding as LText
import System.Random.Stateful (Uniform (uniformM), globalStdGen, uniformByteStringM)
import qualified Web.Cookie as Cookie
import qualified Web.Scotty as Scotty

class IsSession a where
  initialSession :: a

newtype SessionId = SessionId {unSessionId :: BS.ByteString}
  deriving (Show, Eq, Ord)

-- https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length
instance Uniform SessionId where
  uniformM g = SessionId <$> uniformByteStringM 16 g

-- Generate a new session for the current user and expose it as a @SetCookie@.
newSession :: IsSession a => STM.TVar (Map SessionId a) -> IO (SessionId, a, Cookie.SetCookie)
newSession sessions = do
  sessionId <- liftIO $ uniformM globalStdGen
  STM.atomically $ do
    contents <- STM.readTVar sessions
    STM.writeTVar sessions $ Map.insert sessionId initialSession contents
  pure
    ( sessionId,
      initialSession,
      Cookie.defaultSetCookie
        { Cookie.setCookieName = "session",
          Cookie.setCookieValue = Base64.encodeUnpadded $ unSessionId sessionId,
          Cookie.setCookieSameSite = Just Cookie.sameSiteStrict,
          Cookie.setCookieHttpOnly = True,
          Cookie.setCookiePath = Just "/"
          -- Does not work on localhost: the browser doesn't send any cookies
          -- to a non-TLS version of localhost.
          -- TODO: Use mkcert to get a HTTPS setup for localhost.
          -- , Cookie.setCookieSecure = True
        }
    )

newSessionScotty :: IsSession a => STM.TVar (Map SessionId a) -> Scotty.ActionM (SessionId, a)
newSessionScotty sessions = do
  (sessionId, session, setCookie) <- liftIO $ newSession sessions
  -- Scotty is great. Internally, it contains [(HeaderName, ByteString)]
  -- for the headers. The API does not expose this, so here we convert from
  -- bytestring to text and then internally in scotty to bytestring again..
  -- This is quite the unfortunate conversion because the Builder type can
  -- only output lazy bytestrings. Fun times.
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))
  pure (sessionId, session)

getSession :: STM.TVar (Map SessionId a) -> SessionId -> MaybeT Scotty.ActionM (SessionId, a)
getSession sessions sessionId = do
  contents <- liftIO $ STM.atomically $ STM.readTVar sessions
  session <- MaybeT . pure $ Map.lookup sessionId contents
  pure (sessionId, session)

readSessionId :: MaybeT Scotty.ActionM SessionId
readSessionId = do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "session" cookies
  case Base64.decode sessionCookie of
    Left _ -> MaybeT $ pure Nothing
    Right sessionId -> pure $ SessionId sessionId

-- Check if the user has a session cookie.
--
-- If the user doens't have a session set, create a new one and register it
-- with our session registry.
--
-- If the user already has a session set, we don't do anything.
getSessionScotty :: IsSession a => STM.TVar (Map SessionId a) -> Scotty.ActionM (SessionId, a)
getSessionScotty sessions = do
  result <- runMaybeT $ do
    sessionId <- readSessionId
    getSession sessions sessionId
  maybe (newSessionScotty sessions) pure result

-- | @casVersion@ searches for the session with the given @SessionId@ and will compare
-- and swap it, replacing the @old@ session with the @new@ session. Returns @Nothing@
-- if the CAS was unsuccessful.
casSession :: forall a. Eq a => STM.TVar (Map SessionId a) -> SessionId -> a -> a -> STM.STM ()
casSession sessions sessionId old new = do
  contents <- STM.readTVar sessions
  case Map.updateLookupWithKey casSession sessionId contents of
    (Just _, newMap) -> do
      STM.writeTVar sessions newMap
      pure ()
    (Nothing, _map) -> pure ()
  where
    casSession :: SessionId -> a -> Maybe a
    casSession _sessionId current
      | current == old = Just new
      | otherwise = Nothing
