{-# LANGUAGE UnicodeSyntax #-}

module TWC.Crypto.Sha.Native
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

import Prelude.Unicode

import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL

-- -------------------------------------------------------------------------- --
-- * SHA512

sha512Hash ∷ ByteString → ByteArrayL ByteString Sha512Length
sha512Hash = either error id ∘ fromBytes ∘ SHA512.hash

sha512Length ∷ Int
sha512Length = toInt (undefined ∷ Sha512Length)

type Sha512Length = N64

sha512Hash256 ∷ ByteString → ByteArrayL ByteString Sha512_256Length
sha512Hash256 = either error id ∘ fromBytes ∘ SHA512t.hash 256

type Sha512_256Length = N32

sha512_256Length ∷ Int
sha512_256Length = toInt (undefined ∷ Sha512_256Length)

-- -------------------------------------------------------------------------- --
-- * SHA256 legacy hash function

{-# DEPRECATED sha256Hash "Usage of SHA256 in signatures is deprecated. This function must be used only in legacy code." #-}
sha256Hash ∷ ByteString → ByteArrayL ByteString Sha256Length
sha256Hash = either error id ∘ fromBytes ∘ SHA256.hash

sha256Length ∷ Int
sha256Length = toInt (undefined ∷ Sha256Length)

type Sha256Length = N32

