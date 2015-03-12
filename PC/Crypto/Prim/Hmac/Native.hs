-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Hmac.Native
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
-- Module      : PC.Crypto.Prim.Hmac.Native
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--

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

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Sha.Native

-- There is no restriciton on hmac keys other than being bitArray. Hence we
-- don't need a newtype wrapper.

hmacSha512
    :: ByteString -- ^ secret key
    -> ByteString -- ^ data that is authenticated
    -> ByteArrayL Sha512Length
hmacSha512 key dat = either error id . fromBytes . BY.toBytes $ HASH.hmacAlg HASH.SHA512 key dat

hmacSha512_256 :: ByteString -> ByteString -> ByteArrayL Sha512_256Length
hmacSha512_256 key dat = takeL $ hmacSha512 key dat

-- -------------------------------------------------------------------------- --
-- Incremental API

type HmacSha512Ctx = HASH.HMACContext HASH.SHA512

hmacSha512Init
    :: ByteString -- ^ secret key
    -> HmacSha512Ctx
hmacSha512Init = HASH.hmacInit

hmacSha512Update
    :: HmacSha512Ctx
    -> ByteString -- ^ data that is authenticated
    -> HmacSha512Ctx
hmacSha512Update = HASH.hmacUpdate

hmacSha512Finalize
    :: HmacSha512Ctx
    -> ByteArrayL Sha512Length
hmacSha512Finalize = either error id . fromBytes . BY.toBytes . HASH.hmacFinalize

hmacSha512_256Finalize
    :: HmacSha512Ctx
    -> ByteArrayL Sha512_256Length
hmacSha512_256Finalize = takeL . hmacSha512Finalize

