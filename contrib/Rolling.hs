-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Rolling
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
-- Module      : PC.Crypto.Rolling
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Rolling
    ( RollingSeed(..)
    , RollingScheme
    , Rolling_HMAC_SHA512_500000(..)
    , Rolling_HMAC_SHA512_5000(..)
    , Rolling(..)
    , rollingSeedCreate
    , rollingData
    , rollingDataPreviousN
    , rollingKey
    , rollingKeyPreviousN
    ) where

import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word
import Data.Bits
import PC.Bytes.Random
import PC.Bytes.ByteArray
import PC.Crypto.Prim.Class
--import PC.Crypto.Prim.Sha
import PC.Crypto.Prim.Hmac
import System.IO.Unsafe

class RollingScheme scheme where
    rollingReferential :: scheme -> Int

data Rolling_HMAC_SHA512_500000 = Rolling_HMAC_SHA512_500000

instance RollingScheme Rolling_HMAC_SHA512_500000 where
    rollingReferential _ = 500000

-- | This scheme is here for testing the properties of the
-- rolling algorithm faster than the previous one
data Rolling_HMAC_SHA512_5000 = Rolling_HMAC_SHA512_5000

instance RollingScheme Rolling_HMAC_SHA512_5000 where
    rollingReferential _ = 5000

newtype RollingSeed = RollingSeed ByteString
    deriving (Show,Eq,Bytes)

data Rolling a = Rolling
    { rollingIteration :: Int
    , rollingObj       :: a
    }

instance Functor Rolling where
  fmap f (Rolling it obj) = Rolling it (f obj)
instance Show a => Show (Rolling a) where
  show (Rolling i1 o1) = ("Rolling " ++ show i1 ++ " " ++ show o1)
instance Eq a => Eq (Rolling a) where
  (Rolling i1 o1) == (Rolling i2 o2) = i1 == i2 && o1 == o2

-- | Create a new Rolling Seed
rollingSeedCreate :: IO RollingSeed
rollingSeedCreate = RollingSeed <$> getRandom 128

-- | Derive the N previous version of the data
rollingDataPreviousN :: RollingScheme scheme
                     => scheme
                     -> Int                -- ^ outLen
                     -> Int                -- ^ number of time to derive
                     -> Rolling ByteString -- ^ the initial version
                     -> Rolling ByteString -- ^ the result
rollingDataPreviousN _ outLen n (Rolling currentVersion x)
  | currentVersion - n >= 0 = Rolling (currentVersion-n) (loopHash currentVersion n x)
  | otherwise               = error ("cannot derive past version 0: current=" ++ show currentVersion ++ " n=" ++ show n)
  where
    loopHash :: Int -> Int -> ByteString -> ByteString
    loopHash _  0 !z = B.take outLen z
    loopHash it i !z = loopHash (it-1) (i-1) $ bsXor z (toBytes $ hmacSha512 (B.take outLen z) (toBS $ fromIntegral it))

    bsXor orig b = B.pack $ B.zipWith xor orig b

    -- big endian encoding of Word32
    toBS :: Word32 -> ByteString
    toBS w = B.pack [a,b,c,d]
      where a = fromIntegral (w `shiftR` 24)
            b = fromIntegral ((w `shiftR` 16) .&. 0xff)
            c = fromIntegral ((w `shiftR` 8) .&. 0xff)
            d = fromIntegral (w .&. 0xff)

rollingData :: RollingScheme scheme
            => scheme
            -> Int                -- ^ size of bytestring to generate
            -> Int                -- ^ version
            -> RollingSeed        -- ^ initial rolling seed
            -> Rolling ByteString
rollingData rollingScheme outLen n (RollingSeed d)
    | n < 0            = error "derivative key version negative"
    | n >= referential = error "derivative key limit reached. cannot compute"
    | otherwise        = rollingDataPreviousN rollingScheme outLen (referential - n) (Rolling referential d)
  where
        referential = rollingReferential rollingScheme

rollingKeyPreviousN :: (AsymmetricCrypto secretKey publicKey, RollingScheme scheme)
                    => scheme
                    -> Int               -- ^ number of time to derive
                    -> Rolling secretKey
                    -> Rolling secretKey
rollingKeyPreviousN scheme n r@(Rolling _ secretKey) =
    either error id . fromBytes <$> rollingDataPreviousN scheme (B.length $ toBytes secretKey) n (fmap toBytes r)

rollingKey :: (RollingScheme scheme, AsymmetricCrypto secretKey publicKey)
           => scheme
           -> Int                 -- ^ version
           -> RollingSeed
           -> Rolling secretKey
rollingKey scheme n rollingSeed = getKey (unsafePerformIO asymmetricKeyGenerate)
  where
        getKey :: AsymmetricCrypto secretKey publicKey
               => secretKey
               -> Rolling secretKey
        getKey secretKey =
            let outLen = B.length . toBytes $ secretKey
             in either error id . fromBytes <$> rollingData scheme outLen n rollingSeed
