-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE DataKinds #-}

module PC.Crypto.Prim.Sha.Native
(
-- * SHA512
  sha512Hash
, sha512Hash256
, sha512Length
, Sha512Length
, sha512_256Length
, Sha512_256Length

-- * SHA256 Legacy Hash Function
, sha256Hash
, sha256Length
, Sha256Length

) where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA512t as SHA512t

import Data.ByteString (ByteString)
import Data.Proxy

import Prelude.Unicode

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

-- -------------------------------------------------------------------------- --
-- * SHA512

sha512Hash ∷ ByteString → ByteArrayL ByteString Sha512Length
sha512Hash = either error id ∘ fromBytes ∘ SHA512.hash

sha512Length ∷ Int
sha512Length = toInt (Proxy ∷ Proxy Sha512Length)

type Sha512Length = 64

sha512Hash256 ∷ ByteString → ByteArrayL ByteString Sha512_256Length
sha512Hash256 = either error id ∘ fromBytes ∘ SHA512t.hash 256

type Sha512_256Length = 32

sha512_256Length ∷ Int
sha512_256Length = toInt (Proxy ∷ Proxy Sha512_256Length)

-- -------------------------------------------------------------------------- --
-- * SHA256 legacy hash function

sha256Hash ∷ ByteString → ByteArrayL ByteString Sha256Length
sha256Hash = either error id ∘ fromBytes ∘ SHA256.hash

sha256Length ∷ Int
sha256Length = toInt (Proxy ∷ Proxy Sha256Length)

type Sha256Length = 32

