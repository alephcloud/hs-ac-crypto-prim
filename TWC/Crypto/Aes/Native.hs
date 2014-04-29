{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | sjcl.mode.cbc
--
module TWC.Crypto.Aes.Native
( AesKey256
, aesKey256Length
, AesKey256Length
, AesIV
, AesIVLength
, aesIVLength
, aesBlockLength
, AesBlockLength
, generateAesKey256
, generateAesIV
, aes256CbcEncrypt
, aes256CbcDecrypt
, AesSize
) where

import Control.Applicative

import "cipher-aes" Crypto.Cipher.AES
import Crypto.Padding

import Data.ByteString (ByteString)

import Prelude.Unicode

import TWC.Crypto.Codec
import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL

import TypeLevel.Number.Classes

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

type AesKey256Length = N32

generateAesKey256 ∷ IO AesKey256
generateAesKey256 = AesKey256 <$> randomBytesL

aesKey256Length ∷ Int
aesKey256Length = toInt (undefined ∷ AesKey256Length)

generateAesIV ∷ IO AesIV
generateAesIV = AesIV <$> randomBytesL

type AesIVLength = AesBlockLength

aesIVLength ∷ Int
aesIVLength = aesBlockLength

type AesBlockLength = N16

aesBlockLength ∷ Int
aesBlockLength = toInt (undefined ∷ AesBlockLength)

-- | AES-256 encryption with CBC mode and PKCS#5 padding
--
aes256CbcEncrypt ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcEncrypt k iv d =
    encryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) $ padPKCS5 aesBlockLength d

-- | AES-256 decryption with CBC mode and PKCS#5 padding
--
aes256CbcDecrypt ∷ AesKey256 → AesIV → ByteString → ByteString
aes256CbcDecrypt k iv d =
    unpadPKCS5 $ decryptCBC (initAES (toBytes k ∷ ByteString)) (toBytes iv ∷ ByteString) d

type family AesSize n
type instance AesSize n = AesSize' n AesBlockLength (Compare n AesBlockLength)

type family AesSize' n m b
type instance AesSize' n m IsGreater = AesSize' n (Add m AesBlockLength) (Compare n (Add m AesBlockLength))
type instance AesSize' n m IsEqual = m
type instance AesSize' n m IsLesser = m

