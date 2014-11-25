-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.ChaCha
    (
    -- * ChaCha types
      ChaCha
    , ChaChaKey256Length
    , ChaChaKey128Length
    , ChaChaNonceLength
    , ChaChaKey256
    , ChaChaKey128
    , ChaChaNonce

    -- * Methods
    , chachaInit256
    , chachaInit128
    , chachaEncrypt
    ) where

import Data.ByteString (ByteString)
import Data.Byteable (Byteable)
import "crypto-random" Crypto.Random
import qualified Crypto.Cipher.ChaCha as ChaCha

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

type ChaCha = ChaCha.State

type ChaChaKey128Length = 16
type ChaChaKey256Length = 32
type ChaChaNonceLength = 8

newtype ChaChaKey256 = ChaChaKey256 (ByteArrayL ChaChaKey256Length)
    deriving (Eq,Ord,Code64,Code16)

newtype ChaChaKey128 = ChaChaKey128 (ByteArrayL ChaChaKey128Length)
    deriving (Eq,Ord,Code64,Code16)

newtype ChaChaNonce = ChaChaNonce (ByteArrayL ChaChaNonceLength)
    deriving (Eq,Ord,Code64,Code16)

instance Bytes ChaChaKey256 where
    toBytes (ChaChaKey256 bytes) = toBytes bytes
    fromBytes = fmap ChaChaKey256 . fromBytes

instance BytesL ChaChaKey256 where
    type ByteLengthL ChaChaKey256 = ChaChaKey256Length
    toBytesL (ChaChaKey256 bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaKey256 . fromBytesL

instance Bytes ChaChaKey128 where
    toBytes (ChaChaKey128 bytes) = toBytes bytes
    fromBytes = fmap ChaChaKey128 . fromBytes

instance BytesL ChaChaKey128 where
    type ByteLengthL ChaChaKey128 = ChaChaKey128Length
    toBytesL (ChaChaKey128 bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaKey128 . fromBytesL

instance Bytes ChaChaNonce where
    toBytes (ChaChaNonce bytes) = toBytes bytes
    fromBytes = fmap ChaChaNonce . fromBytes

instance BytesL ChaChaNonce where
    type ByteLengthL ChaChaNonce = ChaChaNonceLength
    toBytesL (ChaChaNonce bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaNonce . fromBytesL

chachaInit256 :: ChaChaKey256 -> ChaChaNonce -> ChaCha
chachaInit256 key nonce = ChaCha.initialize 20 (toBytes key) (toBytes nonce)

chachaInit128 :: ChaChaKey128 -> ChaChaNonce -> ChaCha
chachaInit128 key nonce = ChaCha.initialize 20 (toBytes key) (toBytes nonce)

chachaEncrypt :: ChaCha -> ByteString -> (ByteString, ChaCha)
chachaEncrypt = ChaCha.combine
