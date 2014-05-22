-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

-- | sjcl.mode.cbc
--
module TWC.Crypto.Aes.Native
( AesKey256
, aesKey256Length
, AesKey256Length
, AesIV
, AesIVLength
, aesIVLength
, aesCBCResidual
, aesBlockLength
, AesBlockLength
, generateAesKey256
, generateAesIV
, aes256CbcEncrypt
, aes256CbcEncryptNoPad
, aes256CbcDecrypt
, aes256CbcDecryptNoPad
, AesSize
) where

import Control.Applicative

import Crypto.Cipher.AES

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Proxy
import Data.Monoid.Unicode

import GHC.TypeLits

import Prelude.Unicode

import TWC.Crypto.Codec
import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL

padPKCS7 ∷ Int → ByteString → ByteString
padPKCS7 blockLength a = case blockLength - (B.length a `rem` blockLength) of
    0 → a ⊕ B.replicate blockLength (fromIntegral blockLength)
    i → a ⊕ B.replicate i (fromIntegral i)

unpadPKCS7 ∷ ByteString → ByteString
unpadPKCS7 a = B.take (B.length a - fromIntegral (B.last a)) a

aesCBCResidual ∷ ByteString → Maybe AesIV
aesCBCResidual b = either (const Nothing) Just $ fromBytes $ B.drop (len - aesBlockLength) b
  where len = B.length b

-- | AES keys have a particular length. Right now we
-- don't enforce this on the type level, still we use
-- a newtype wrapper to tag this class of bitArray.
--
newtype AesKey256 = AesKey256 (ByteArrayL ByteString AesKey256Length)
    deriving (Eq, Ord, Code64, Code16)

instance Bytes AesKey256 where
    type ByteArrayImpl AesKey256 = ByteString
    toBytes (AesKey256 bytes) = toBytes bytes
    fromBytes = fmap AesKey256 ∘ fromBytes

instance BytesL AesKey256 where
    type ByteLengthL AesKey256 = AesKey256Length
    toBytesL (AesKey256 bytes) = toBytesL bytes
    fromBytesL = fmap AesKey256 ∘ fromBytesL

-- | AES IVs have a particular length. Right now we
-- don't enforce this on the type level, still we use
-- a newtype wrapper to tag this class of bitArray.
--
newtype AesIV = AesIV (ByteArrayL ByteString AesIVLength)
    deriving (Eq, Ord)

instance Bytes AesIV where
    type ByteArrayImpl AesIV = ByteString
    toBytes (AesIV bytes) = toBytes bytes
    fromBytes = fmap AesIV ∘ fromBytes

instance BytesL AesIV where
    type ByteLengthL AesIV = AesIVLength
    toBytesL (AesIV bytes) = toBytesL bytes
    fromBytesL = fmap AesIV ∘ fromBytesL

type AesKey256Length = 32

generateAesKey256 ∷ IO AesKey256
generateAesKey256 = AesKey256 <$> randomBytesL

aesKey256Length ∷ Int
aesKey256Length = toInt (Proxy ∷ Proxy AesKey256Length)

generateAesIV ∷ IO AesIV
generateAesIV = AesIV <$> randomBytesL

type AesIVLength = AesBlockLength

aesIVLength ∷ Int
aesIVLength = aesBlockLength

type AesBlockLength = 16

aesBlockLength ∷ Int
aesBlockLength = toInt (Proxy ∷ Proxy AesBlockLength)

-- | AES-256 encryption with CBC mode and PKCS#5 padding
--
aes256CbcEncrypt ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcEncrypt k iv d =
    encryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) $ padPKCS7 aesBlockLength d

-- | AES-256 encryption with CBC mode and no padding
--
aes256CbcEncryptNoPad ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcEncryptNoPad k iv d =
    encryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) d

-- | AES-256 decryption with CBC mode and PKCS#5 padding
--
aes256CbcDecrypt ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcDecrypt k iv d =
    unpadPKCS7 $ decryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) d

-- | AES-256 decryption with CBC mode without padding
--
aes256CbcDecryptNoPad ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcDecryptNoPad k iv d =
    decryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) d

type family AesSize (n ∷ Nat) ∷ Nat
type instance AesSize n = AesSize' n AesBlockLength (CmpNat n AesBlockLength)

type family AesSize' (n ∷ Nat) (m ∷ Nat) (b ∷ Ordering) ∷ Nat
type instance AesSize' n m GT = AesSize' n (m + AesBlockLength) (CmpNat n (m + AesBlockLength))
type instance AesSize' n m EQ = m
type instance AesSize' n m LT = m

