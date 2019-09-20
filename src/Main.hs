{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Main where

import Control.Monad.Except
import Crypto.Random.Types (MonadRandom)
import Data.Bifunctor (first)
import Data.Functor ((<&>))
import Data.List (find)
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import GHC.Generics (Generic)
import Jose.Jwa (JwsAlg(RS256))
import Jose.Jwt
  ( Payload (Claims), IntDate (IntDate), Jwt (Jwt), JwtClaims (..)
  , JwtContent (Jws), JwtEncoding (JwsEncoding), decode, encode )
import Network.HTTP.Types.Status
import Text.Digestive ((.:))
import Text.Read (readMaybe)
import Text.Regex (matchRegex, mkRegexWithOpts)
import TextShow (showt)
import Web.Scotty (scotty)
import Web.Scotty.Trans
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Text.Digestive.Aeson as DF
import qualified Text.Digestive.Form as DF
import qualified Text.Digestive.Types as DF

data Auth = Auth
  { authEmail    :: Text
  , authPassword :: Text
  } deriving Generic
instance Aeson.ToJSON Auth

data UserError = UserErrorBadAuth Auth
               | UserErrorNotFound UserId
  deriving Generic
instance Aeson.ToJSON UserError

data TokenError = TokenErrorNotFound
                | TokenErrorMalformed String
                | TokenErrorExpired
                | TokenErrorUserIdNotFound
  deriving Generic
instance Aeson.ToJSON TokenError

data User = User
  { userEmail :: Text
  , userToken :: Text
  } deriving (Show, Generic)
instance Aeson.ToJSON User

type UserId = Int
type Token = Text
type CurrentUser = (Token, UserId)

data UserRepo m = UserRepo
  { findUserByAuth :: Auth -> m (Maybe (UserId, User))
  , findUserById   :: Int -> m (Maybe User)
  }

data Tokens m = Tokens
  { generateToken :: UserId -> m Token
  , resolveToken  :: Token -> m (Either TokenError CurrentUser)
  }

main :: IO ()
main = do
  let userRepo = userRepoDummy :: UserRepo IO
  tokens <- tokensIO
  scotty 3000 $ do
    post "/api/users/login" $ do
      auth <- parseJsonBody authForm
      user <- lift (login userRepo tokens auth) >>= either userHandler pure
      json user
    get "/api/user" $ do
      curUser <- requireUser tokens
      user <- lift (getUser userRepo curUser) >>= either userHandler pure
      json user

--
-- "Instances" for records of functions.
--

userRepoDummy :: Monad m => UserRepo m
userRepoDummy = UserRepo
  { findUserByAuth = \auth ->
    -- NOTE: Doesn't check password, since this is dummy example.
    return $ find ((== authEmail auth) . userEmail . snd) users
  , findUserById = \id -> return $ lookup id users
  }
 where
  users = [ (0, User { userEmail = "bob@gmail.com", userToken = "" })
          , (1, User { userEmail = "foo@gmail.com", userToken = "" }) ]

tokensIO :: (MonadIO m, MonadRandom m) => m (Tokens m)
tokensIO = do
  parsed <- Aeson.eitherDecodeStrict <$> liftIO (BS.readFile "secrets/jwk.sig")
  let jwks           = either (error . ("Invalid JWK file: " <>)) pure parsed
      expirationSecs = 2 * 60 * 60
  return Tokens { generateToken = generateToken' jwks expirationSecs
                , resolveToken  = resolveToken' jwks
                }
 where
  generateToken' jwks expirationSecs uid = do
    curTime <- liftIO getPOSIXTime
    let claim = JwtClaims { jwtIss = Nothing
                          , jwtSub = Just $ showt uid
                          , jwtAud = Nothing
                          , jwtExp = Just $ IntDate $ curTime + expirationSecs
                          , jwtNbf = Nothing
                          , jwtIat = Nothing
                          , jwtJti = Nothing
                          }
        claimStr = BSL.toStrict $ Aeson.encode claim
    (Jwt encoded) <- either (error . ("Failed to encode JWT: " <>) . show) id
                 <$> encode jwks (JwsEncoding RS256) (Claims claimStr)
    return $ decodeUtf8 encoded
  resolveToken' jwks token = do
    curTime <- liftIO getPOSIXTime
    eitherJwt <- decode jwks (Just (JwsEncoding RS256)) (encodeUtf8 token)
    return $ do
      jwt <- first (TokenErrorMalformed . show) eitherJwt
      claimsRaw <- case jwt of
        Jws (_, claimsRaw) -> Right claimsRaw
        _                  -> Left $ TokenErrorMalformed "Not Jws"
      jwtClaims <- first TokenErrorMalformed
                 $ Aeson.eitherDecode $ BSL.fromStrict claimsRaw
      let (IntDate expiredAt) = fromMaybe (IntDate curTime) $ jwtExp jwtClaims
      when (expiredAt < curTime) $ Left TokenErrorExpired
      userId <- maybe (Left TokenErrorUserIdNotFound) Right
              $ jwtSub jwtClaims >>= readMay
      return (token, userId)
  readMay = readMaybe . T.unpack

--
-- Service code
--

login :: Monad m => UserRepo m -> Tokens m -> Auth -> m (Either UserError User)
login UserRepo{..} Tokens{..} auth = findUserByAuth auth >>= \case
  Nothing             -> return $ Left (UserErrorBadAuth auth)
  Just (userId, user) -> do
    token <- generateToken userId
    return $ Right user { userToken = token }

getUser :: Functor f => UserRepo f -> CurrentUser -> f (Either UserError User)
getUser UserRepo{..} (token, id) = findUserById id <&> \case
  Nothing   -> Left $ UserErrorNotFound id
  Just user -> Right user { userToken = token }

--
-- Helper functions for Scotty
--

requireUser :: (Monad m, ScottyError e) => Tokens m -> ActionT e m CurrentUser
requireUser toks = getCurrentUser toks >>= either tokenErrorHandler pure
 where tokenErrorHandler e = status status401 >> json e >> finish

getCurrentUser :: (Monad m, ScottyError e)
               => Tokens m -> ActionT e m (Either TokenError CurrentUser)
getCurrentUser Tokens{..} = header "Authorization" >>= \case
  Nothing        -> return $ Left TokenErrorNotFound
  Just headerVal -> lift $ resolveToken token
   where token = T.strip $ TL.toStrict $ TL.drop 6 headerVal

parseJsonBody :: (MonadIO m, ScottyError e)
              => DF.Form [Text] m a -> ActionT e m a
parseJsonBody form = do
  val <- jsonData `rescue` malformedJSONHandler
  (_, result) <- lift $ DF.digestJSON form val
  case result of
    Nothing ->
      status status422 >> json ("Could not parse JSON form" :: Text) >> finish
    Just v -> return v

userHandler :: (Monad m, ScottyError e) => UserError -> ActionT e m a
userHandler err = status status400 >> json err >> finish

malformedJSONHandler :: (Monad m, ScottyError e) => err -> ActionT e m a
malformedJSONHandler _ =
  status status422 >> json ("Malformed JSON payload" :: Text) >> finish

--
-- Validation code
--

authForm :: Monad m => DF.Form [Text] m Auth
authForm = Auth
  <$> "email" .: DF.validate emailValidation (DF.text Nothing)
  <*> "password" .: DF.validate passwordValidation (DF.text Nothing)

minLength :: Int -> Text -> DF.Result Text Text
minLength n str = if T.length str >= n
  then DF.Success str
  else DF.Error $ "Minimum length is: " <> showt n

matchesRegex :: v -> String -> Text -> DF.Result v Text
matchesRegex err regex str =
  if isJust . matchRegex (mkRegexWithOpts regex True True) . T.unpack $ str
    then DF.Success str
    else DF.Error err

emailValidation :: Text -> DF.Result [Text] Text
emailValidation = DF.conditions
  [ matchesRegex
    "Not a valid email" "^[a-zA-Z0-9\\.\\+\\-]+@[a-zA-Z0-9]+\\.[a-zA-Z0-9]+$" ]

usernameValidation :: Text -> DF.Result [Text] Text
usernameValidation = DF.conditions
  [ minLength 3
  , matchesRegex "Should be alphanumeric" "^[a-zA-Z0-9]+$"
  ]

passwordValidation :: Text -> DF.Result [Text] Text
passwordValidation = DF.conditions [minLength 5]
