{-# LANGUAGE ScopedTypeVariables #-}

module Session (SessionsVar, emptySessions, withSession) where

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

newtype SessionId = SessionId {unSessionId :: BS.ByteString}
  deriving (Show, Eq, Ord)

type SessionsVar s = STM.TVar (Map SessionId s)

emptySessions :: IO (SessionsVar s)
emptySessions = STM.newTVarIO Map.empty

-- https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length
instance Uniform SessionId where
  uniformM g = SessionId <$> uniformByteStringM 16 g

getSessionId :: Scotty.ActionM (Maybe SessionId)
getSessionId = runMaybeT $ do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "session" cookies
  case Base64.decode sessionCookie of
    Left _ -> MaybeT $ pure Nothing
    Right sessionId -> pure $ SessionId sessionId

createSessionId :: Scotty.ActionM SessionId
createSessionId = do
  sessionId <- liftIO $ uniformM globalStdGen
  let setCookie =
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
  -- Scotty is great. Internally, it contains [(HeaderName, ByteString)]
  -- for the headers. The API does not expose this, so here we convert from
  -- bytestring to text and then internally in scotty to bytestring again..
  -- This is quite the unfortunate conversion because the Builder type can
  -- only output lazy bytestrings. Fun times.
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))
  pure sessionId

withSession :: SessionsVar s -> (Maybe s -> Scotty.ActionM (Maybe s)) -> Scotty.ActionM ()
withSession var f = do
  (sessionId, session) <-
    getSessionId >>= \case
      Nothing -> do
        -- If the request didn't contain a session id, create a new one and
        -- return that no session is present
        newSessionId <- createSessionId
        pure (newSessionId, Nothing)
      Just sessionId -> do
        -- Otherwise, check if such a session id is known
        existingSession <- liftIO $
          STM.atomically $ do
            sessions <- STM.readTVar var
            case Map.lookup sessionId sessions of
              Nothing -> pure Nothing
              Just session -> do
                -- If it is known, remove it from the map, to indicate that it's being processed
                -- This is to prevent race conditions with updates
                STM.writeTVar var $ Map.delete sessionId sessions
                pure $ Just session
        case existingSession of
          Nothing -> do
            -- If the session id wasn't known, create a new one and
            -- return that no session is present
            newSessionId <- createSessionId
            pure (newSessionId, Nothing)
          Just session -> do
            pure (sessionId, Just session)

  newSession <- f session

  case newSession of
    Nothing -> pure ()
    Just session ->
      liftIO $
        STM.atomically $
          STM.modifyTVar var $ Map.insert sessionId session
