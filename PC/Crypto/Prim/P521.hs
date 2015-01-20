-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
-- |
-- Module      : PC.Crypto.Prim.P521
-- Copyright   : (c) 2013-2014 PivotCloud, Inc
-- License     : All Right Reserved
-- Maintainer  : support@pivotmail.com
--
-- P521 support
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
