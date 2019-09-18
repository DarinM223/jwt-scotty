{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Control.Monad.Except
import Data.Aeson (ToJSON)
import Data.Maybe (isJust)
import Data.Text (Text)
import GHC.Generics
import Network.HTTP.Types.Status
import Text.Digestive ((.:))
import Text.Regex
import TextShow
import Web.Scotty (scotty)
import Web.Scotty.Trans
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Text.Digestive.Aeson as DF
import qualified Text.Digestive.Form as DF
import qualified Text.Digestive.Types as DF

data Auth = Auth
  { authEmail    :: Text
  , authPassword :: Text
  } deriving Generic
instance ToJSON Auth

newtype UserError = UserErrorBadAuth Auth
  deriving Generic
instance ToJSON UserError

data TokenError = TokenErrorNotFound
  deriving Generic
instance ToJSON TokenError

data User = User
  { userEmail :: Text
  , userToken :: Text
  } deriving Generic
instance ToJSON User

data CurrentUser = CurrentUser

data UserRepo m = UserRepo
  { findUserByAuth :: Auth -> m (Maybe (Int, User))
  , findUserById   :: Int -> m (Maybe User)
  }

newtype TokenRepo m = TokenRepo { generateToken :: Int -> m Text }
newtype Service m = Service
  { resolveToken :: Text -> m (Either TokenError CurrentUser) }

main :: IO ()
main = do
  userRepo <- undefined
  tokenRepo <- undefined
  service <- undefined
  scotty 3000 $ do
    post "/api/users/login" $ do
      auth <- parseJsonBody authForm
      user <- login userRepo tokenRepo auth >>= either userHandler pure
      json user
    get "/api/user" $ do
      user <- requireUser service
      undefined

--
-- Service code
--

login :: Monad m
      => UserRepo m -> TokenRepo m -> Auth -> m (Either UserError User)
login UserRepo{..} TokenRepo{..} auth = findUserByAuth auth >>= \case
  Nothing             -> return $ Left (UserErrorBadAuth auth)
  Just (userId, user) -> do
    token <- generateToken userId
    return $ Right user { userToken = token }

requireUser :: (Monad m, ScottyError e) => Service m -> ActionT e m CurrentUser
requireUser service = getCurrentUser service >>= either tokenErrorHandler pure
 where tokenErrorHandler e = status status401 >> json e >> finish

getCurrentUser :: (Monad m, ScottyError e)
               => Service m -> ActionT e m (Either TokenError CurrentUser)
getCurrentUser Service{..} = header "Authorization" >>= \case
  Nothing        -> return (Left TokenErrorNotFound)
  Just headerVal -> lift $ resolveToken token
   where token = TL.toStrict $ TL.drop 6 headerVal

--
-- Helper functions for Scotty
--

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
