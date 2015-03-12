-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- Example2
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
-- Module      : Example2
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
module Main where

import PC.Crypto.Prim.Curve25519
import PC.Bytes.ByteArrayL
import PC.Bytes.ByteArray
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Applicative
import Control.Monad

main = do
    -- generate secret key / public key from System RNG
    secretKey <- either error id . fromBytesL <$> randomBytesL
    let publicKey = createPublicKey secretKey

    putStrLn $ show $ toBytes publicKey

    return ()
