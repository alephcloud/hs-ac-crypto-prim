-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds #-}
module PC.Crypto.Prim.Ecc.Key
( PublicKey(..)
, SecretKey(..)

, getPk
, dhSecret
, dh

, KeyPair(..)
, generateKeyPair

-- * Internal
, ecScalarRandom
, ecScalarRandomNonZero
, ecRandomGenerator

, ecFieldToBytes

-- ** Misc
, bnSqrtModP

) where

import qualified Data.ByteString as B
import Control.Applicative hiding (empty)

import Data.Monoid

import Control.Monad
import Control.Monad.Error

import Data.String
import Data.Proxy
import Data.Word

import GHC.TypeLits

import Prelude hiding (length, splitAt, take, drop)

import PC.Crypto.Prim.Ecc.Ops

import PC.Bytes.Codec
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

import PC.Crypto.Prim.Bn

import PC.Bytes.Utils

-- -------------------------------------------------------------------------- --
-- * Random 'EcScalar'

ecScalarRandom :: (EcCurve curve, MonadIO u) => u (EcScalar curve)
ecScalarRandom = liftIO (getRandom Proxy)
  where getRandom :: EcCurve curve => Proxy curve -> IO (EcScalar curve)
        getRandom proxy = ecScalar <$> bnRandom (curveR $ curveFromProxy proxy)

ecScalarRandomNonZero :: (EcCurve curve, MonadIO io) => io (EcScalar curve)
ecScalarRandomNonZero = liftIO (getRandom Proxy)
  where getRandom :: EcCurve curve => Proxy curve -> IO (EcScalar curve)
        getRandom proxy = do
            r <- bnRandom (curveR $ curveFromProxy proxy)
            if r == 0 then getRandom proxy else return $ ecScalar r

-- -------------------------------------------------------------------------- --
-- * Generating a random generator for the curve group of order curveR

ecRandomGenerator :: (EcCurve curve, MonadIO u) => u (EcPoint curve)
ecRandomGenerator = liftIO $ ecPointGen <$> ecScalarRandom

-- -------------------------------------------------------------------------- --
-- * Ec Scalar Serialization
--
-- TODO Move this into a separate module
--

instance EcCurve curve => Bytes (EcScalar curve) where
    toBytes = ecScalarToBytes
    fromBytes = ecScalarFromBytes

instance (EcCurve curve, Code16 Bn) => Code16 (EcScalar curve) where
    to16 = to16 . getEcScalarBn
    from16 = fmap ecScalar . from16

instance (EcCurve curve, Code64 Bn) => Code64 (EcScalar curve) where
    to64 = to64 . getEcScalarBn
    from64 = fmap ecScalar . from64

ecScalarFromBytes :: EcCurve curve => BackendByteArray -> Either String (EcScalar curve)
ecScalarFromBytes bs = from Proxy
  where from :: EcCurve curve => Proxy curve -> Either String (EcScalar curve)
        from proxy =
            let len = curveFieldLength $ curveFromProxy proxy
             in if B.length bs == len
                    then ecScalar <$> fromBytes bs
                    -- else Left "invalid length for scalar"
                    else Left ("invalid length for scalar: got: " ++ show (B.length bs) ++ " expecting " ++ show len)

ecScalarToBytes :: EcCurve curve => EcScalar curve -> BackendByteArray
ecScalarToBytes bn = padLeft 0 (getFieldLength Proxy bn) $ toBytes $ getEcScalarBn bn
  where getFieldLength :: EcCurve curve => Proxy curve -> EcScalar curve -> Int
        getFieldLength proxy _ = curveFieldLength $ curveFromProxy proxy

-- -------------------------------------------------------------------------- --
-- * Point Serialization
--
-- TODO Move this into a separate module
--

instance EcCurve curve => Bytes (EcPoint curve) where
    toBytes = doTo Proxy
      where doTo :: EcCurve curve => Proxy curve -> EcPoint curve -> BackendByteArray
            doTo proxy p = curvePointToBin (curveFromProxy proxy) p
    fromBytes bs = doFrom Proxy
      where doFrom :: EcCurve curve => Proxy curve -> Either String (EcPoint curve)
            doFrom proxy = curvePointFromBin (curveFromProxy proxy) bs

instance EcCurve curve => Code16 (EcPoint curve) where
    to16 = to16 . toBytes
    from16 = fromBytes <=< from16

instance EcCurve curve => Code64 (EcPoint curve) where
    to64 = to64 . toBytes
    from64 = fromBytes <=< from64

instance EcCurve curve => Show (EcPoint curve) where
    show = to16

ecFieldFromBytes :: EcCurve curve => curve -> BackendByteArray -> Either String Bn
ecFieldFromBytes curve bs
    | B.length bs == len = fromBytes bs
    | otherwise          = Left "invalid size for ec field element"
  where len = curveFieldLength curve

ecFieldToBytes :: EcCurve curve => curve -> Bn -> BackendByteArray
ecFieldToBytes curve = padLeft 0 (curveFieldLength curve) . toBytes

-- | This is not a general method but works only for the moduli of curve 192 and 521:
--
-- > curveP `mod` 4 == 3
--
-- This condition is /not/ checked.
--
-- Note that the result may be positive or negative modulus curveP.
--
bnSqrtModP :: Bn -> Bn -> Bn
bnSqrtModP square prime = s
    where
    s = bnPowerMod square expo prime
    expo = (bnHalve . bnHalve) $ (prime + 1)

-- -------------------------------------------------------------------------- --
-- * Keys

newtype SecretKey curve = SecretKey { unSk :: EcScalar curve }
    deriving (Show, Eq, Ord)

deriving instance (EcCurve curve, Code64 Bn) => Code64 (SecretKey curve)
deriving instance (EcCurve curve, Code16 Bn) => Code16 (SecretKey curve)

instance EcCurve curve => Bytes (SecretKey curve) where
    toBytes = toBytes . unSk
    fromBytes = fmap SecretKey . fromBytes

newtype PublicKey curve = PublicKey { unPk :: EcPoint curve }
    deriving (Show, Eq, Code64, Code16)

-- | This instance of 'Ord' for 'PublicKey' does not
-- represent any topological properties. It is meant
-- primarily for data structures like binary search
-- trees.
instance EcCurve curve => Ord (PublicKey curve) where
    compare (PublicKey a) (PublicKey b) = compare (ecX a, ecY a) (ecX b, ecY b)

-- | We support two different encodings:
--
-- 1. the normal compresssed encoding as generated by the 'ToJSON' instance
--    of 'PublicKey'.
--
-- 2. an uncompressed encoding. The uncompressed encoding consists of the
--    concatenation of the affine x and y conordinates byte serialization.
--
-- The length of the input determines which encoding is used.
--
instance EcCurve curve => Bytes (PublicKey curve) where
    toBytes = toBytes . unPk
    fromBytes bytes = PublicKey <$> fromBytes bytes
{-
        (fromBytes bytes <|>
            (ecPoint
                <$> fromBytes (take ecScalarLength bytes)
                <*> fromBytes (drop ecScalarLength bytes)))
-}

data KeyPair curve = KeyPair
    { jEcKeyPairPk :: PublicKey curve
    , jEcKeyPairSk :: SecretKey curve
    }

-- | Create EC key pair
--
generateKeyPair :: EcCurve curve => MonadIO u => u (KeyPair curve)
generateKeyPair = liftIO $ do
    secBn <- ecScalarRandom
    let pkPoint = ecPointGen secBn
    return $ KeyPair (PublicKey pkPoint) (SecretKey secBn)

-- | Basic Diffie-Hellman
--
dh :: EcCurve curve => SecretKey curve -> PublicKey curve -> EcPoint curve
dh (SecretKey sec) (PublicKey pub) = ecPointMul pub sec

-- | Basic Diffie-Hellman
--
-- Returns the affine x-coordinate of the resulting point
--
dhSecret :: EcCurve curve => SecretKey curve -> PublicKey curve -> EcScalar curve
dhSecret sk pk = ecScalar . ecX $ dh sk pk

getPk :: EcCurve curve => SecretKey curve -> PublicKey curve
getPk (SecretKey sec) = PublicKey $ ecPointGen sec

-- -------------------------------------------------------------------------- --
-- Parser

{-
pPk :: (EcCurve curve, Bytes (PublicKey curve)) => Parser (PublicKey curve)
pPk = pTakeBytes <?> "pPk"

pSk :: (EcCurve curve, Bytes (SecretKey curve)) => Parser (SecretKey curve)
pSk = pTakeBytesL <?> "pSk"

pScalar :: (EcCurve curve, Bytes (EcScalar curve)) => Parser (EcScalar curve)
pScalar = pTakeBytesL <?> "pScalar"

pEcPoint :: (EcCurve curve, Bytes (EcPoint curve)) => Parser (EcPoint curve)
pEcPoint = pTakeBytesL <?> "pEcPoint"

-}
