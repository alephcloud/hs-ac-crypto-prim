-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

-- |
-- Module      : PC.Crypto.Prim.P256
-- Copyright: Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
-- License: All Rights Reserved, see LICENSE file of the package
-- Maintainer  : support@pivotmail.com
--
-- P256 support

{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module PC.Crypto.Prim.P256
    ( 
    -- NIST P256 instance
      P256PublicKey(..)
    , P256SecretKey(..)
    , P256EcdsaSignature(..)
    ) where

import Control.Applicative
import Control.DeepSeq (NFData)
import PC.Bytes.ByteArray
import PC.Crypto.Prim.Imports
import PC.Crypto.Prim.Class
import qualified PC.Crypto.Prim.Ecc as Ecc
import qualified PC.Crypto.Prim.Ecdsa as ECDSA

newtype P256PublicKey = P256PublicKey { unP256P :: Ecc.PublicKey Ecc.P256 }
    deriving (Show,Eq,Bytes,NFData)

newtype P256SecretKey = P256SecretKey { unP256S :: Ecc.SecretKey Ecc.P256 }
    deriving (Show,Eq,Bytes,NFData)

newtype P256EcdsaSignature = P256EcdsaSignature (ECDSA.EcdsaSignature Ecc.P256)
    deriving (Show,Bytes,Eq,NFData)

instance AsymmetricCrypto P256SecretKey P256PublicKey where
    asymmetricKeyGenerate = P256SecretKey . Ecc.SecretKey <$> Ecc.ecScalarRandom
    asymmetricGetPublic   = P256PublicKey . Ecc.getPk . unP256S

instance DiffieHellmanAlgorithm P256SecretKey P256PublicKey where
    dhSecret (P256SecretKey s) (P256PublicKey p) = DhSecret $ toBytes $ Ecc.dhSecret s p

instance ToACN P256SecretKey where
    toACN (P256SecretKey p) = [AcnBytes $ toBytes p]
instance FromACN P256SecretKey where
    fromACN (AcnBytes b:l) = (\r -> (P256SecretKey r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance ToACN P256PublicKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN P256PublicKey where
    fromACN (AcnBytes b:l) = (\r -> (P256PublicKey r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance SignatureAlgorithm P256EcdsaSignature P256SecretKey P256PublicKey where
    sign secretKey a   = P256EcdsaSignature <$> ECDSA.sign (unP256S secretKey) (toBytes a)
    verify publicKey a (P256EcdsaSignature sig) = ECDSA.verify (unP256P publicKey) (toBytes a) sig

instance ToACN P256EcdsaSignature where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN P256EcdsaSignature where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "ACN EcdsaSignature: invalid sequence"
