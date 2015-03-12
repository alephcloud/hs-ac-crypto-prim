-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Poly1305
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
-- Module      : PC.Crypto.Prim.Poly1305
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.Poly1305
    (
    -- * Poly1305 types
      MacKey
    , MacKeyLength
    , Poly1305Length
    , Poly1305
    , Poly1305Ctx
    -- * Poly1305 methods
    , macInitialize
    , macUpdate
    , macFinalize
    , mac
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable (Byteable)
import qualified Data.Byteable as Byteable
import "crypto-random" Crypto.Random
import qualified Crypto.MAC.Poly1305 as Poly1305

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

type Poly1305Ctx = Poly1305.Ctx

newtype Poly1305 = Poly1305 (ByteArrayL Poly1305Length)
    deriving (Eq,Ord,Code64,Code16)

macInitialize :: MacKey -> Poly1305Ctx
macInitialize = Poly1305.initialize . toBytes

macUpdate :: Poly1305Ctx -> ByteString -> Poly1305Ctx
macUpdate = Poly1305.update

macFinalize :: Poly1305Ctx -> Poly1305
macFinalize = either error id . fromBytes . Byteable.toBytes . Poly1305.finalize

mac :: MacKey -> ByteString -> Poly1305
mac key bs = either error id $ fromBytes $ Byteable.toBytes $ Poly1305.auth (toBytes key) bs

type MacKeyLength = 32
type Poly1305Length = 16

newtype MacKey = MacKey (ByteArrayL MacKeyLength)
    deriving (Eq,Ord,Code64,Code16)

instance Bytes MacKey where
    toBytes (MacKey bytes) = toBytes bytes
    fromBytes = fmap MacKey . fromBytes

instance BytesL MacKey where
    type ByteLengthL MacKey = MacKeyLength
    toBytesL (MacKey bytes) = toBytesL bytes
    fromBytesL = fmap MacKey . fromBytesL

instance Bytes Poly1305 where
    toBytes (Poly1305 p) = toBytes p
    fromBytes b
        | B.length b == 16 = fmap Poly1305 $ fromBytes b
        | otherwise        = Left "poly1305: not valid length"

instance BytesL Poly1305 where
    type ByteLengthL Poly1305 = Poly1305Length
    toBytesL (Poly1305 bytes) = toBytesL bytes
    fromBytesL = fmap Poly1305 . fromBytesL
