-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Ed25519
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
-- Module      : PC.Crypto.Prim.Ed25519
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.Ed25519
    ( Ed25519SecretKey
    , Ed25519PublicKey
    , Ed25519Signature
    ) where

import Control.Applicative
import Control.DeepSeq
import Data.ByteString (ByteString)
import qualified Crypto.Sign.Ed25519 as Ed25519
import PC.Bytes.ByteArray
import PC.Crypto.Prim.Class
import PC.Crypto.Prim.Imports

newtype Ed25519SecretKey = Ed25519SecretKey Ed25519.SecretKey
    deriving (Show,Bytes,Eq,NFData)

newtype Ed25519PublicKey = Ed25519PublicKey Ed25519.PublicKey
    deriving (Show,Bytes,Eq,NFData)

newtype Ed25519Signature = Ed25519Signature Ed25519.Signature
    deriving (Show,Bytes,Eq,NFData)

instance AsymmetricCrypto Ed25519SecretKey Ed25519PublicKey where
    asymmetricKeyGenerate                    = Ed25519SecretKey <$> createSecret
    asymmetricGetPublic (Ed25519SecretKey k) = Ed25519PublicKey $ createPublic k

instance SignatureAlgorithm Ed25519Signature Ed25519SecretKey Ed25519PublicKey where
    sign   (Ed25519SecretKey sec) a                        = return $ Ed25519Signature $ Ed25519.sign' sec (toBytes a)
    verify (Ed25519PublicKey pub) a (Ed25519Signature sig) = Ed25519.verify' pub (toBytes a) sig

instance ToACN Ed25519SecretKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN Ed25519SecretKey where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "ACN Ed25519SecretKey: invalid sequence"

instance ToACN Ed25519PublicKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN Ed25519PublicKey where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "ACN Ed25519PublicKey: invalid sequence"

instance ToACN Ed25519Signature where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN Ed25519Signature where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "ACN Ed25519Signature: invalid sequence"


createKeypair :: IO (Ed25519.PublicKey, Ed25519.SecretKey)
createKeypair = Ed25519.createKeypair

createSecret :: IO Ed25519.SecretKey
createSecret = snd `fmap` createKeypair

createPublic :: Ed25519.SecretKey -> Ed25519.PublicKey
createPublic = Ed25519.toPublicKey
