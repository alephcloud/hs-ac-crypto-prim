-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Bn.Native
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
-- Module      : PC.Crypto.Prim.Bn.Native
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module PC.Crypto.Prim.Bn.Native
(
-- * Big Numbers
  Bn
, bn
, bnZero
, bnOne
, bnMod
, bnAdd
, bnSub
, bnMul
, bnMulMod
, bnPower
, bnPowerMod
, bnInverseMod
, bnHalve
, bnLength
, bnRandom

-- * Unit tests
, prop0
, prop1
, prop2

) where

import Control.Applicative
import Control.Monad

import Crypto.Random

import qualified Data.ByteString as B
import Data.Word

import GHC.Integer.GMP.Internals

import PC.Bytes.ByteArray

type Bn = Integer

instance Bytes Bn where
    toBytes = fromList . bnToBytes
    fromBytes = Right . bytesToBn . toList

instance Code64 Bn where
    to64 = to64 . toBytes
    from64 = fromBytes <=< from64

instance Code16 Bn where
    to16 = to16 . toBytes
    from16 = fromBytes <=< from16

bn :: Int -> Bn
bn = fromIntegral

bnZero :: Bn
bnZero = 0

bnOne :: Bn
bnOne = 1

bnMod :: Bn -> Bn -> Bn
bnMod = mod

bnAdd :: Bn -> Bn -> Bn
bnAdd = (+)

bnSub :: Bn -> Bn -> Bn
bnSub = (-)

bnMul :: Bn -> Bn -> Bn
bnMul = (*)

bnMulMod :: Bn -> Bn -> Bn -> Bn
bnMulMod a b c = (a * b) `mod` c

bnPower :: Bn -> Bn -> Bn
bnPower = (^)

bnPowerMod :: Bn -> Bn -> Bn -> Bn
bnPowerMod = powModInteger

bnInverseMod :: Bn -> Bn -> Bn
bnInverseMod 0 _ = 0
bnInverseMod a b = case recipModInteger a b of
    0 -> error "illegal inverse modulus"
    n -> n

bnHalve :: Bn -> Bn
bnHalve a = a `div` 2

bnLength :: Bn -> Int
bnLength i = floor (logBase (256 :: Double) (fromInteger i)) + 1

bnRandom :: Integer -> IO Bn
bnRandom i = do
    let l = bnLength i
    rng <- cprgCreate <$> createEntropyPool :: IO SystemRNG
    return $ bytesToBn (B.unpack . fst . cprgGenerate l $ rng) `mod` i

-- | Big endian serialization of /positive/ integers
--
bnToBytes :: Bn -> [Word8]
bnToBytes n
    | n == 0 = [0]     -- logically [] would make sense, but for in practice that would cause problems
    | n > 0 = go n []
    | otherwise = error "bnToBytes accepts only positive numbers"
    where
    go i b
        | i == 0 = b
        -- i < 256 = (fromIntegral i:b)
        | otherwise = let (x,i') = i `quotRem` 256 in go x (fromIntegral i':b)

bytesToBn :: [Word8] -> Bn
bytesToBn b = go 0 b
    where
    go i [] = i
    go i (h:t) = go ((i * 256) + fromIntegral h) t

-- -------------------------------------------------------------------------- --
-- Unit tests

prop0 :: Bn -> Bool
prop0 x = x == bytesToBn (bnToBytes x)

prop1 :: Bn -> IO Bool
prop1 i = do
    r <- bnRandom i
    return $ (bnLength r <= bnLength i) && r <= i

prop2 :: Bn -> Bn -> Bool
prop2 a b = not (a <= b) || (bnLength a <= bnLength b)

