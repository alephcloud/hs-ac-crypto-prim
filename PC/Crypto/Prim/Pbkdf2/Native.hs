-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE ScopedTypeVariables #-}

module PC.Crypto.Prim.Pbkdf2.Native
(
-- * PBKDF2
  pbkdf2Sha512
, pbkdf2Sha512L
, pbkdf2Sha512Async
, pbkdf2Sha512AsyncL

) where

import Data.ByteString (ByteString)
import Data.Proxy

import Control.Concurrent
import Control.Monad
import qualified Crypto.PBKDF.Core as PB

import GHC.TypeLits

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Hmac.Native
import PC.Crypto.Prim.Sha.Native

import Prelude.Unicode

pbkdf2Sha512
    ∷ ByteString -- ^ password
    → ByteString -- ^ salt
    → Int        -- ^ number of rounds
    → Int        -- ^ size of result in bytes
    → ByteString
pbkdf2Sha512 = pbkdf2

pbkdf2Sha512L
    ∷ ∀ m. KnownNat m
    ⇒ ByteString    -- ^ password
    → ByteString    -- ^ salt
    → Int           -- ^ number of rounds
    → ByteArrayL ByteString m
pbkdf2Sha512L password salt rounds = either error id ∘ fromBytes $ pbkdf2 password salt rounds (toInt (Proxy ∷ Proxy m))

type ByteStringResultCallback = ByteString → IO ()

-- | FIXME: make this exception safe!
--
pbkdf2Sha512Async
    ∷ ByteString                -- ^ password
    → ByteString                -- ^ salt
    → Int                       -- ^ number of rounds
    → Int                       -- ^ size of result in bytes
    → ByteStringResultCallback  -- ^ callback function for the result
    → α                         -- ^ ignored
    → IO ()
pbkdf2Sha512Async password salt rounds size cb _ = void ∘ forkIO $ do
    cb $ pbkdf2Sha512 password salt rounds size

type ByteArrayLResultCallback n = ByteArrayL ByteString n → IO ()

-- | FIXME: make this exception safe!
--
pbkdf2Sha512AsyncL
    ∷ KnownNat n
    ⇒ ByteString                 -- ^ password
    → ByteString                 -- ^ salt
    → Int                        -- ^ number of rounds
    → ByteArrayLResultCallback n -- ^ callback function for the result
    → α                          -- ^ ignored
    → IO ()
pbkdf2Sha512AsyncL password salt rounds cb _ = void ∘ forkIO $ do
    cb $ pbkdf2Sha512L password salt rounds

-- -------------------------------------------------------------------------- --
-- Low Level PBKDF2 Setup

pbkdf2
    ∷ ByteString
    → ByteString
    → Int
    → Int
    → ByteString
pbkdf2 pwd salt rounds outLen = PB.pbkdf2 $ PB.PBKDF
    { PB.pbkdf_PRF = PB.PRF
        { PB.prf_hmac = \a b → toBytes $ hmacSha512 a b
        , PB.prf_hash = toBytes ∘ sha512Hash
        , PB.prf_hLen = sha512Length
        }
    , PB.pbkdf_P = pwd
    , PB.pbkdf_S = salt
    , PB.pbkdf_c = rounds
    , PB.pbkdf_dkLen = outLen
    }

