-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.P521
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
-- Module      : PC.Crypto.Prim.P521
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.P521
    ( 
    -- NIST P521 instance
      P521PublicKey(..)
    , P521SecretKey(..)
    , P521EcdsaSignature(..)
    ) where

import Control.Applicative
import Control.DeepSeq (NFData)
import PC.Bytes.ByteArray
import PC.Crypto.Prim.Imports
import PC.Crypto.Prim.Class
import qualified PC.Crypto.Prim.Ecc as Ecc
import qualified PC.Crypto.Prim.Ecdsa as ECDSA

------------------------------------------------------------------------
-- NIST P521 instance
------------------------------------------------------------------------

newtype P521PublicKey = P521PublicKey { unP521P :: Ecc.PublicKey Ecc.P521 }
    deriving (Show,Eq,Bytes,NFData)

newtype P521SecretKey = P521SecretKey { unP521S :: Ecc.SecretKey Ecc.P521 }
    deriving (Show,Eq,Bytes,NFData)

newtype P521EcdsaSignature = P521EcdsaSignature (ECDSA.EcdsaSignature Ecc.P521)
    deriving (Show,Bytes,Eq,NFData)

instance AsymmetricCrypto P521SecretKey P521PublicKey where
    asymmetricKeyGenerate = P521SecretKey . Ecc.SecretKey <$> Ecc.ecScalarRandom
    asymmetricGetPublic   = P521PublicKey . Ecc.getPk . unP521S

instance DiffieHellmanAlgorithm P521SecretKey P521PublicKey where
    dhSecret (P521SecretKey s) (P521PublicKey p) = DhSecret $ toBytes $ Ecc.dhSecret s p

instance ToACN P521SecretKey where
    toACN (P521SecretKey p) = [AcnBytes $ toBytes p]
instance FromACN P521SecretKey where
    fromACN (AcnBytes b:l) = (\r -> (P521SecretKey r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance ToACN P521PublicKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN P521PublicKey where
    fromACN (AcnBytes b:l) = (\r -> (P521PublicKey r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance SignatureAlgorithm P521EcdsaSignature P521SecretKey P521PublicKey where
    sign secretKey a   = P521EcdsaSignature <$> ECDSA.sign (unP521S secretKey) (toBytes a)
    verify publicKey a (P521EcdsaSignature sig) = ECDSA.verify (unP521P publicKey) (toBytes a) sig

instance ToACN P521EcdsaSignature where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN P521EcdsaSignature where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "ACN EcdsaSignature: invalid sequence"
