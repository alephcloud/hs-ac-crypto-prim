-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.ChaCha
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
-- Module      : PC.Crypto.Prim.ChaCha
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
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
    deriving (Eq,Ord)

newtype ChaChaKey128 = ChaChaKey128 (ByteArrayL ChaChaKey128Length)
    deriving (Eq,Ord)

newtype ChaChaNonce = ChaChaNonce (ByteArrayL ChaChaNonceLength)
    deriving (Eq,Ord)

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
