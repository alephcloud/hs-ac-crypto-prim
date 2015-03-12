-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- Poly1305
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
-- Module      : Poly1305
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
module Main where

import Data.ByteString.Base16 as B16
import Data.ByteString.Base64 as B64
import PC.Crypto.Prim.Poly1305
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Bytes.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad
import Control.Applicative

withBase64 :: String -> B.ByteString -> (B.ByteString -> IO a) -> IO a
withBase64 s bs f =
    case B64.decode bs of
        Left err -> error ("decoding Base64 " ++ show s ++ " : " ++ show err) 
        Right v  -> f v

main = do
    args <- getArgs
    
    case args of
        ["init"] -> do
            macKey <- (either error id . fromBytes <$> getRandom 32) :: IO MacKey
            putStrLn $ BC.unpack $ B64.encode $ toBytes $ macKey
        [mackey64,dat64] ->
            withBase64 "mac-key" (BC.pack mackey64) $ \mackeyBs ->
            withBase64 "data" (BC.pack dat64)       $ \dat      -> do
                case fromBytes mackeyBs of
                    Left err     -> error ("invalid poly1305 mac key: " ++ err)
                    Right macKey -> do
                        let result = mac macKey dat
                        putStrLn $ BC.unpack $ B16.encode $ toBytes result
        _            -> error "usage: poly1305 [ init | <mackey-base64> <data-base64> ]"
