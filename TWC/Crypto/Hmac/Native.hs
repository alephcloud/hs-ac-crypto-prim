{-# LANGUAGE UnicodeSyntax #-}

module TWC.Crypto.Hmac.Native
( hmacSha512
, hmacSha512_256
) where

import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.MAC.HMAC as HMAC

import Data.ByteString (ByteString)

import Prelude.Unicode

import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL
import TWC.Crypto.Sha.Native

-- There is no restriciton on hmac keys other than being bitArray. Hence we
-- don't need a newtype wrapper.

-- Block length of SHA512 in bytes
sha512BlockLength ∷ Int
sha512BlockLength = 128

hmacSha512 ∷ ByteString → ByteString → ByteArrayL ByteString Sha512Length
hmacSha512 key dat = either error id ∘ fromBytes $ HMAC.hmac SHA512.hash sha512BlockLength key dat

hmacSha512_256 ∷ ByteString → ByteString → ByteArrayL ByteString Sha512_256Length
hmacSha512_256 key dat = takeL $ hmacSha512 key dat

