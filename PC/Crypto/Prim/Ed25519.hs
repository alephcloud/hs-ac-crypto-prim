-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--

module PC.Crypto.Prim.Ed25519
    ( Ed25519SecretKey
    , Ed25519PublicKey
    , Ed25519Signature
    ) where

import Data.ByteString (ByteString)
import Data.Byteable (Byteable)
import qualified Crypto.Sign.Ed25519 as Ed25519
import PC.Crypto.Prim.Class
import PC.Crypto.Prim.Imports

newtype Ed25519SecretKey = Ed25519SecretKey Ed25519.SecretKey
    deriving (Show,Bytes,Eq,NFData)

newtype Ed25519PublicKey = Ed25519PublicKey Ed25519.PublicKey
    deriving (Show,Bytes,Eq,NFData)

instance AsymmetricCrypto Ed25519SecretKey Ed25519PublicKey where
    assymmetricKeyGenerate                    = Ed25519SecretKey <$> Ed25519.createSecret
    assymmetricGetPublic (Ed25519SecretKey k) = Ed25519PublicKey $ Ed25519.createPublic k

instance SignatureAlgorithm Ed25519Signature Ed25519SecretKey Ed25519PublicKey where
    sign   (Ed25519SecretKey sec) = Ed25519.sign' sec
    verify (Ed25519PublicKey pub) = Ed25519.verify' pub

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

createKeypair :: IO (Ed25519.PublicKey, Ed25519.SecretKey)
createKeypair = Ed25519.createKeypair

createSecret :: IO Ed25519.SecretKey
createSecret = snd `fmap` createKeypair

createPublic :: Ed25519.SecretKey -> Ed25519.PublicKey
createPublic = Ed25519.toPublicKey

sign :: Ed25519.SecretKey -> ByteString -> Ed25519.Signature
sign = Ed25519.sign'

verify :: Ed25519.PublicKey -> ByteString -> Ed25519.Signature -> Bool
verify = Ed25519.verify'
