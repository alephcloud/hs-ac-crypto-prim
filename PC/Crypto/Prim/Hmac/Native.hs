-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}

module PC.Crypto.Prim.Hmac.Native
( hmacSha512
, hmacSha512_256

-- * Incremental API
, HmacSha512Ctx
, hmacSha512Init
, hmacSha512Update
, hmacSha512Finalize
, hmacSha512_256Finalize
) where

import qualified Crypto.Hash as HASH
import qualified Crypto.MAC as HASH

import Data.ByteString (ByteString)
import qualified Data.Byteable as BY (toBytes)

import Prelude.Unicode

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Sha.Native

-- There is no restriciton on hmac keys other than being bitArray. Hence we
-- don't need a newtype wrapper.

hmacSha512
    ∷ ByteString -- ^ secret key
    → ByteString -- ^ data that is authenticated
    → ByteArrayL ByteString Sha512Length
hmacSha512 key dat = either error id ∘ fromBytes ∘ BY.toBytes $ HASH.hmacAlg HASH.SHA512 key dat

hmacSha512_256 ∷ ByteString → ByteString → ByteArrayL ByteString Sha512_256Length
hmacSha512_256 key dat = takeL $ hmacSha512 key dat

-- -------------------------------------------------------------------------- --
-- Incremental API

type HmacSha512Ctx = HASH.HMACContext HASH.SHA512

hmacSha512Init
    ∷ ByteString -- ^ secret key
    → HmacSha512Ctx
hmacSha512Init = HASH.hmacInit

hmacSha512Update
    ∷ HmacSha512Ctx
    → ByteString -- ^ data that is authenticated
    → HmacSha512Ctx
hmacSha512Update = HASH.hmacUpdate

hmacSha512Finalize
    ∷ HmacSha512Ctx
    → ByteArrayL ByteString Sha512Length
hmacSha512Finalize = either error id ∘ fromBytes ∘ BY.toBytes ∘ HASH.hmacFinalize

hmacSha512_256Finalize
    ∷ HmacSha512Ctx
    → ByteArrayL ByteString Sha512_256Length
hmacSha512_256Finalize = takeL ∘ hmacSha512Finalize

