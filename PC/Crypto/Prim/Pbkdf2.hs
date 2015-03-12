-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Pbkdf2
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
-- Module      : PC.Crypto.Prim.Pbkdf2
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--

module PC.Crypto.Prim.Pbkdf2
    ( pbkdf2Sha512
    ) where

import Crypto.KDF.PBKDF2
import Crypto.Hash (SHA512(..))
import Data.ByteString (ByteString)

pbkdf2Sha512 :: ByteString -- ^ password
             -> ByteString -- ^ salt
             -> Int        -- ^ number of rounds
             -> Int        -- ^ size of result in bytes
             -> ByteString
pbkdf2Sha512 password salt iter outLen = generate (prfHMAC SHA512) $ Parameters password salt iter outLen
