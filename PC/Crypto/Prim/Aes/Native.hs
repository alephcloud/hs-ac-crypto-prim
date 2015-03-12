-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Aes.Native
--
-- Please feel free to contact us at licensing@pivotmail.com with any
-- contributions, additions, or other feedback; we would love to hear from
-- you.
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may
-- not use this file except in compliance with the License. You may obtain a
-- copy of the License at http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations
-- under the License.
--
-- |
-- Module      : PC.Crypto.Prim.Aes.Native
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module PC.Crypto.Prim.Aes.Native
( AesKey256
, aesKey256Length
, AesKey256Length
, AesIV
, AesIVLength
, aesIVLength
, AesGcmIV(..)
, aesCBCResidual
, aesBlockLength
, AesBlockLength
, generateAesKey256
, generateAesIV
, aes256CbcEncrypt
, aes256CbcEncryptNoPad
, aes256CbcDecrypt
, aes256CbcDecryptNoPad
, aes256GcmEncrypt
, aes256GcmDecrypt
, AesSize
, padPKCS7
, unpadPKCS7
) where

import Control.Applicative

import Crypto.Cipher.AES
import Crypto.Cipher.Types (AuthTag(..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.Byteable as B (toBytes)

import Data.Proxy
import Data.Monoid

import GHC.TypeLits

import PC.Bytes.Codec
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

padPKCS7 :: Int -> ByteString -> ByteString
padPKCS7 blockLength a = case blockLength - (B.length a `rem` blockLength) of
    0 -> a `mappend` B.replicate blockLength (fromIntegral blockLength)
    i -> a `mappend` B.replicate i (fromIntegral i)

unpadPKCS7 :: ByteString -> ByteString
unpadPKCS7 a = B.take (B.length a - fromIntegral (B.last a)) a

aesCBCResidual :: ByteString -> Maybe AesIV
aesCBCResidual b = either (const Nothing) Just $ fromBytes $ B.drop (len - aesBlockLength) b
  where len = B.length b

-- | AES keys have a particular length. Right now we
-- don't enforce this on the type level, still we use
-- a newtype wrapper to tag this class of bitArray.
--
newtype AesKey256 = AesKey256 (ByteArrayL AesKey256Length)
    deriving (Eq, Ord, Code64, Code16)

instance Bytes AesKey256 where
    toBytes (AesKey256 bytes) = toBytes bytes
    fromBytes = fmap AesKey256 . fromBytes

instance BytesL AesKey256 where
    type ByteLengthL AesKey256 = AesKey256Length
    toBytesL (AesKey256 bytes) = toBytesL bytes
    fromBytesL = fmap AesKey256 . fromBytesL

-- | AES IVs have a particular length. Right now we
-- don't enforce this on the type level, still we use
-- a newtype wrapper to tag this class of bitArray.
--
newtype AesIV = AesIV (ByteArrayL AesIVLength)
    deriving (Eq, Ord)

instance Bytes AesIV where
    toBytes (AesIV bytes) = toBytes bytes
    fromBytes = fmap AesIV . fromBytes

instance BytesL AesIV where
    type ByteLengthL AesIV = AesIVLength
    toBytesL (AesIV bytes) = toBytesL bytes
    fromBytesL = fmap AesIV . fromBytesL

-- | AES GCM IVs -- at least 12 bytes
newtype AesGcmIV = AesGcmIV ByteString
    deriving (Eq, Ord)

instance Bytes AesGcmIV where
    toBytes (AesGcmIV bytes) = bytes
    fromBytes b
        | B.length b < 12 = Left ("invalid IV size for GCM operation: expecting at least 12 bytes, got " ++ (show $ B.length b) ++ " bytes")
        | otherwise       = Right $ AesGcmIV b

type AesKey256Length = 32

generateAesKey256 :: IO AesKey256
generateAesKey256 = AesKey256 <$> randomBytesL

aesKey256Length :: Int
aesKey256Length = toInt (Proxy :: Proxy AesKey256Length)

generateAesIV :: IO AesIV
generateAesIV = AesIV <$> randomBytesL

type AesIVLength = AesBlockLength

aesIVLength :: Int
aesIVLength = aesBlockLength

type AesBlockLength = 16

aesBlockLength :: Int
aesBlockLength = toInt (Proxy :: Proxy AesBlockLength)

-- | AES-256 encryption with CBC mode and PKCS#5 padding
--
aes256CbcEncrypt :: AesKey256 -> AesIV -> ByteString -> ByteString
aes256CbcEncrypt k iv d =
    encryptCBC (initAES (toBytes k :: ByteString)) (toBytes iv :: ByteString) $ padPKCS7 aesBlockLength d

-- | AES-256 encryption with CBC mode and no padding
--
aes256CbcEncryptNoPad :: AesKey256 -> AesIV -> ByteString -> ByteString
aes256CbcEncryptNoPad k iv d =
    encryptCBC (initAES (toBytes k :: ByteString)) (toBytes iv :: ByteString) d

-- | AES-256 decryption with CBC mode and PKCS#5 padding
--
aes256CbcDecrypt :: AesKey256 -> AesIV -> ByteString -> ByteString
aes256CbcDecrypt k iv d =
    unpadPKCS7 $ decryptCBC (initAES (toBytes k :: ByteString)) (toBytes iv :: ByteString) d

-- | AES-256 decryption with CBC mode without padding
--
aes256CbcDecryptNoPad :: AesKey256 -> AesIV -> ByteString -> ByteString
aes256CbcDecryptNoPad k iv d =
    decryptCBC (initAES (toBytes k :: ByteString)) (toBytes iv :: ByteString) d

-- | GCM encryption
aes256GcmEncrypt :: AesKey256 -> AesGcmIV -> ByteString -> ByteString -> ByteString
aes256GcmEncrypt k iv hdr d =
    let (b,tag) = encryptGCM (initAES (toBytes k :: ByteString)) (toBytes iv) hdr d
     in B.append b (B.toBytes tag)

-- | GCM Decryption
aes256GcmDecrypt :: AesKey256 -> AesGcmIV -> ByteString -> ByteString -> Maybe ByteString
aes256GcmDecrypt k iv hdr cipherText
    | B.length cipherText < 16 = Nothing
    | otherwise                =
        let (encrypted, expectedTag) = B.splitAt (B.length cipherText - 16) cipherText
            (plain, tag)             = decryptGCM (initAES (toBytes k :: ByteString)) (toBytes iv) hdr encrypted
         in if AuthTag expectedTag == tag then Just plain else Nothing

type AesSize n = AesSize' n AesBlockLength (CmpNat n AesBlockLength)
type family AesSize' (n :: Nat) (m :: Nat) (b :: Ordering) :: Nat where
    AesSize' n m GT = AesSize' n (m + AesBlockLength) (CmpNat n (m + AesBlockLength))
    AesSize' n m EQ = m
    AesSize' n m LT = m

