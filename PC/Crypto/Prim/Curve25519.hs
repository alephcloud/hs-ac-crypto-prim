-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module PC.Crypto.Prim.Curve25519
    ( Curve25519SecretKey
    , Curve25519PublicKey
    ) where

import Control.DeepSeq

import PC.Bytes.Codec
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Bytes.Utils

import PC.Crypto.Prim.Class
import PC.Crypto.Prim.Imports

import qualified Crypto.DH.Curve25519 as Curve25519

import qualified Data.ByteString as B

newtype Curve25519SecretKey = SecretKey Curve25519.SecretKey
    deriving (Show, Eq, NFData)
newtype Curve25519PublicKey = PublicKey Curve25519.PublicKey
    deriving (Show, Eq, NFData)

type SecretKeyLength = 32
type PublicKeyLength = 32

secretKeyLength = 32
publicKeyLength = 32

instance AsymmetricCrypto Curve25519SecretKey Curve25519PublicKey where
    asymmetricKeyGenerate = createSecretKey
    asymmetricGetPublic   = createPublicKey

instance DiffieHellmanAlgorithm Curve25519SecretKey Curve25519PublicKey where
    dhSecret (SecretKey secret) (PublicKey public) =
        DhSecret $ Curve25519.curve25519 secret public

instance ToACN Curve25519SecretKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN Curve25519SecretKey where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance ToACN Curve25519PublicKey where
    toACN p = [AcnBytes $ toBytes p]
instance FromACN Curve25519PublicKey where
    fromACN (AcnBytes b:l) = (\r -> (r, l)) `fmap` fromBytes b
    fromACN _              = Left "invalid sequence"

instance Bytes Curve25519SecretKey where
    toBytes (SecretKey (Curve25519.SecretKey bs)) = bs
    fromBytes b = if B.length b == secretKeyLength
                    then Right $ SecretKey $ Curve25519.SecretKey b
                    else Left "curve25519: secret key: not valid length. expecting 32 bytes"

instance BytesL Curve25519SecretKey where
    type ByteLengthL Curve25519SecretKey = SecretKeyLength
    toBytesL (SecretKey (Curve25519.SecretKey bs)) = unsafeFromBytes $ padLeft 0 secretKeyLength $ toBytes bs
    fromBytesL = fromBytes . toBytes

instance Bytes Curve25519PublicKey where
    toBytes (PublicKey (Curve25519.PublicKey bs)) = bs
    fromBytes b = if B.length b == publicKeyLength
                    then Right $ PublicKey $ Curve25519.PublicKey b
                    else Left "curve25519: public key: not valid length. expecting 32 bytes"

instance BytesL Curve25519PublicKey where
    type ByteLengthL Curve25519PublicKey = PublicKeyLength
    toBytesL (PublicKey (Curve25519.PublicKey bs)) = unsafeFromBytes $ padLeft 0 publicKeyLength $ toBytes bs
    fromBytesL = fromBytes . toBytes

dh (SecretKey k) (PublicKey p) = Curve25519.curve25519 k p

createKeypair = do
    (pub, sec) <- Curve25519.createKeypair
    return (PublicKey pub, SecretKey sec)
createSecretKey = (SecretKey . snd) `fmap` Curve25519.createKeypair
createPublicKey (SecretKey k) = PublicKey $ Curve25519.createPublicKey k
