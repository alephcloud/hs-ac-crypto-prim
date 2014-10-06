-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module PC.Crypto.Prim.Ecdsa
( EcdsaSignature(..)
, EcdsaSignatureLength
, ecdsaSignatureLength
, sign
, signWith
, verify
, verifyLegacy
) where

import Control.Applicative
import Control.Monad.IO.Class

import Data.Proxy

import GHC.TypeLits

import Prelude hiding (take, drop)
import Prelude.Unicode

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Bn
import PC.Crypto.Prim.Sha

import PC.Bytes.Utils
import PC.Crypto.Prim.Ecc

-- -------------------------------------------------------------------------- --
-- * ECDSA

newtype EcdsaSignature = EcdsaSignature { unEcdsaSignature ∷ BackendByteArrayL EcdsaSignatureLength }
    deriving (Show, Eq, Ord, Code64, Code16)

type EcdsaSignatureLength = EcScalarLength + EcScalarLength

ecdsaSignatureLength ∷ Int
ecdsaSignatureLength = toInt (Proxy ∷ Proxy EcdsaSignatureLength)

instance Bytes EcdsaSignature where
    toBytes = toBytes ∘ unEcdsaSignature
    fromBytes = fmap EcdsaSignature ∘ fromBytes

instance BytesL EcdsaSignature where
    type ByteLengthL EcdsaSignature = EcdsaSignatureLength
    toBytesL = unEcdsaSignature
    fromBytesL = Right ∘ EcdsaSignature

sign
    ∷ MonadIO μ
    ⇒ SecretKey
    → BackendByteArray
    → μ EcdsaSignature
sign sk content = do
    k ← liftIO $ (+ 1) <$> bnRandom (curveR - 1) -- exclude zero
    return $ signWith sk content k

signWith
    ∷ SecretKey
    → BackendByteArray
    → Bn
    → EcdsaSignature
signWith (SecretKey sk) content k =
    let r = (ecX $ ecPointMul curveG (ecScalar k)) `mod` curveR -- we should assert that r ≠ 0. Won't happen...
        s = bnMulMod (sh + (r * skBn)) (bnInverseMod k curveR) curveR
    in  EcdsaSignature $ toBytesL (ecScalar r) % toBytesL (ecScalar s)
  where
    sh = unsafeFromBytes ∘ take ecFieldLength ∘ toBytes $ hash
    hash = sha512Hash content
    skBn = ecScalarBn $ sk

verify
    ∷ PublicKey
    → BackendByteArray
    → EcdsaSignature
    → Bool
verify pk dat sig = verify' sha512Hash pk dat sig || verifyLegacy pk dat sig

{-# DEPRECATED verifyLegacy "Usage of SHA256 in signatures is deprecated. This function must be used only in legacy code." #-}
verifyLegacy
    ∷ PublicKey
    → BackendByteArray
    → EcdsaSignature
    → Bool
verifyLegacy = verify' sha256Hash

verify'
    ∷ KnownNat ν
    ⇒ (BackendByteArray → BackendByteArrayL ν)
    → PublicKey
    → BackendByteArray
    → EcdsaSignature
    → Bool
verify' hash (PublicKey pk) content sig =
    r ≠ 0 && ss ≠ 0 && r < curveR && ss < curveR && r2 ≡ r
  where
    r2 = ecX $ ecPointMul2 curveG hG hA pk
    hA = ecScalar $ bnMulMod r s curveR
    hG = ecScalar $ bnMulMod sh s curveR
    s = bnInverseMod ss curveR
    ss = unsafeFromBytes ∘ drop ecFieldLength ∘ toBytes $ sig
    r = unsafeFromBytes ∘ take ecFieldLength ∘ toBytes $ sig
    sh = unsafeFromBytes ∘ take ecFieldLength ∘ toBytes $ hash content

