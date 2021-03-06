-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- Example1
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
-- Module      : Example1
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
module Main where

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.ChaCha
import "crypto-random" Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad

encryptStdin keyFile = do
    entropy <- createEntropyPool
    let rng1          = cprgCreate entropy :: SystemRNG
        (key, rng2)   = cprgGenerate 32 rng1
        (nonce, rng3) = cprgGenerate 8 rng2

    B.writeFile keyFile key
    
    let state = chachaInit256 (either error id $ fromBytes key) (either error id $ fromBytes nonce)
    L.interact (runEncrypt nonce state)
  where runEncrypt nonce state lbs =
            L.chunk nonce (loop state lbs)
        loop state lbs
            | L.null lbs = L.empty
            | otherwise   =
                let (l1,l2) = L.splitAt 1024 lbs 
                    (encrypted, nstate) = chachaEncrypt state (L.toStrict l1)
                 in L.chunk encrypted (loop nstate l2)

decryptStdin keyFile = do
    key <- B.readFile keyFile
    unless (B.length key == 32) $ error "key length must be 256 bits"

    L.interact (runDecrypt key)
  where runDecrypt key lbs =
            let (nonce, lbs') = L.splitAt 8 lbs
                state = chachaInit256 (either error id $ fromBytes key) (either error id $ fromBytes $ L.toStrict nonce)
             in loop state lbs'
        loop state lbs
            | L.null lbs = L.empty
            | otherwise  =
                let (l1,l2) = L.splitAt 1024 lbs
                    (decrypted, nstate) = chachaEncrypt state (L.toStrict l1)
                 in L.chunk decrypted (loop nstate l2)

main = do
    args <- getArgs
    case args of
        ["encrypt",keyFile] -> encryptStdin keyFile
        ["decrypt",keyFile] -> decryptStdin keyFile
        _         -> error "usage: cipher [encrypt|decrypt] <keyfile>"
