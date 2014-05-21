-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds #-}

module TWC.Crypto.Ecc.Key
( PublicKey(..)
, PublicKeyLength
, publicKeyLength
, SecretKey(..)
, SecretKeyLength
, secretKeyLength

, getPk
, dhSecret
, dh

, KeyPair(..)
, generateKeyPair

-- * Internal
, EcScalarLength
, ecScalarLength
, EcPointLength
, ecPointLength
, ecScalarRandom
, ecRandomGenerator

#ifdef __HASTE__
, ecPointFromBinCompressedLAsync
#endif
, ecFieldToBytesL

-- * Binary parser
, pPk
, pSk
, pScalar
, pEcPoint

-- ** Misc
, bnSqrtModP

) where

import Control.Applicative hiding (empty)

import Data.Monoid.Unicode

import Control.Monad
import Control.Monad.Error
import Control.Monad.IO.Class

import Data.String
import Data.Word

import GHC.TypeLits

import Prelude hiding (length, splitAt, take, drop)
import Prelude.Unicode

import TWC.Crypto.Ecc.Ops

import TWC.Crypto.Codec
import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL

import TWC.Crypto.Bn

import TWC.Crypto.Utils

-- -------------------------------------------------------------------------- --
-- * Random 'EcScalar'

ecScalarRandom ∷ MonadIO μ ⇒ μ EcScalar
ecScalarRandom = liftIO $ ecScalar <$> bnRandom curveR

-- -------------------------------------------------------------------------- --
-- * Generating a random generator for the curve group of order curveR

ecRandomGenerator ∷ MonadIO μ ⇒ μ EcPoint
ecRandomGenerator = liftIO $ ecPointMul curveG <$> ecScalarRandom

-- -------------------------------------------------------------------------- --
-- * Ec Scalar Serialization
--
-- TODO Move this into a separate module
--

type EcScalarLength = CurveFieldLength

ecScalarLength ∷ Int
ecScalarLength = curveFieldLength

instance BytesL EcScalar where
    type ByteLengthL EcScalar = EcScalarLength
    toBytesL = ecScalarToBytesL
    fromBytesL = ecScalarFromBytesL

instance Bytes EcScalar where
    type ByteArrayImpl EcScalar = BackendByteArray
    toBytes = padLeft 0 ecScalarLength ∘ toBytes ∘ ecScalarBn
    fromBytes = fmap ecScalar ∘ fromBytes

instance Code16 Bn ⇒ Code16 EcScalar where
    to16 = to16 ∘ ecScalarBn
    from16 = fmap ecScalar ∘ from16

instance Code64 Bn ⇒ Code64 EcScalar where
    to64 = to64 ∘ ecScalarBn
    from64 = fmap ecScalar ∘ from64

ecScalarFromBytesL ∷ BackendByteArrayL EcScalarLength → Either String EcScalar
ecScalarFromBytesL = fmap ecScalar ∘ fromBytes ∘ toBytes

ecScalarToBytesL ∷ EcScalar → BackendByteArrayL EcScalarLength
ecScalarToBytesL = unsafeFromBytes ∘ padLeft 0 ecScalarLength ∘ toBytes ∘ ecScalarBn

-- -------------------------------------------------------------------------- --
-- * Point Serialization
--
-- TODO Move this into a separate module
--

ecPointLength ∷ Int
ecPointLength = curveFieldLength + 1

type EcPointLength = CurveFieldLength + 1

instance Bytes EcPoint where
    type ByteArrayImpl EcPoint = BackendByteArray
    toBytes = toBytes ∘ ecPointToBinCompressedL
    fromBytes = ecPointFromBinCompressedL <=< fromBytes

instance BytesL EcPoint where
    type ByteLengthL EcPoint = EcPointLength
    toBytesL = ecPointToBinCompressedL
    fromBytesL = ecPointFromBinCompressedL

instance Code16 EcPoint where
    to16 = to16 ∘ toBytes
    from16 = fromBytes <=< from16

instance Code64 EcPoint where
    to64 = to64 ∘ toBytes
    from64 = fromBytes <=< from64

instance Show EcPoint where
    show = to16

ecFieldFromBytesL ∷ BackendByteArrayL EcFieldLength → Either String Bn
ecFieldFromBytesL = fromBytes ∘ toBytes

ecFieldToBytesL ∷ Bn → BackendByteArrayL EcFieldLength
ecFieldToBytesL = unsafeFromBytes ∘ padLeft 0 curveFieldLength ∘ toBytes

-- | EcPoiint serialization
--
ecPointToBinCompressedL ∷ EcPoint → BackendByteArrayL EcPointLength
ecPointToBinCompressedL p = prefix % (ecFieldToBytesL ∘ ecX) p
    where
    prefix ∷ BackendByteArrayL 1
    prefix = either error id ∘ fromBytes ∘ fromList $ if (ecY p `mod` 2) ≡ 0 then [2 ∷ Word8] else [3 ∷ Word8]

-- This is not a general method but works only for the moduli of curve 192 and 521
--
ecPointFromBinCompressedL ∷ BackendByteArrayL EcPointLength → Either String EcPoint
ecPointFromBinCompressedL x = do
    let (c ∷ BackendByteArrayL 1, b) = splitL x
    xBn ← ecFieldFromBytesL b
    cBn ← fromBytes $ toBytes c
    yBn ← affineY cBn xBn
    return $ ecPoint xBn yBn

#ifdef __HASTE__
ecPointFromBinCompressedLAsync ∷ BackendByteArrayL EcPointLength → (Either String EcPoint → IO ()) → IO ()
ecPointFromBinCompressedLAsync x cont = do
    let (c ∷ BackendByteArrayL N1, b) = splitL x
    case (,) <$> ecFieldFromBytesL b <*> fromBytes (toBytes c) of
        Right (xBn, cBn) →
            affineYAsync cBn xBn $ \yBn → cont $ ecPoint xBn <$> yBn
        Left e → cont $ Left e
#endif

-- This is not a general method but works for the moduli of the NIST curves p192, p384, p521
-- <http://www.nsa.gov/ia/_files/nist-routines.pdf>
-- and the Koblitz curve secp256k1 <http://www.secg.org/collateral/sec2_final.pdf>.
--
-- In concret this function assume that
--
-- > curveP `mod` 4 ≡ 3
--
-- This condition is /not/ checked.
--
affineY ∷ (Show Bn) ⇒ Bn → Bn → Either String Bn
affineY c x = do
    let t0 = (((bnPowerMod x 3 curveP) - (bnMulMod x 3 curveP)) + curveB) `mod` curveP
    let t1 = bnSqrtModP t0 curveP
    t2 ← if (bnPowerMod t1 2 curveP) ≡ t0
        then return t1
        else Left $ "illegal point: " ⊕ show t1 ⊕ " ^2 = " ⊕ show (bnMulMod t1 t1 curveP)
    return $ if (t2 `mod` 2) ≡ (c `mod` 2)
        then t2
        else curveP - t2

#ifdef __HASTE__
affineYAsync ∷ (Show Bn) ⇒ Bn → Bn → (Either String Bn → IO ()) → IO ()
affineYAsync c x cont = do
    bnPowerModAsync x 3 curveP $ \t00 → do
        let t0 = ((t00 - (bnMulMod x 3 curveP)) + curveB) `mod` curveP
        bnSqrtModPAsync t0 curveP $ \t1 → do
            bnPowerModAsync t1 2 curveP $ \t → do
                if t ≠ t0
                    then cont ∘ Left $ "illegal point: " ⊕ show t1 ⊕ " ^2 = " ⊕ show (bnMulMod t1 t1 curveP)
                    else cont ∘ Right $
                        if (t1 `mod` 2) ≡ (c `mod` 2)
                            then t1
                            else curveP - t1
#endif

-- | This is not a general method but works only for the moduli of curve 192 and 521:
--
-- > curveP `mod` 4 ≡ 3
--
-- This condition is /not/ checked.
--
-- Note that the result may be positive or negative modulus curveP.
--
bnSqrtModP ∷ Bn → Bn → Bn
bnSqrtModP square prime = s
    where
    s = bnPowerMod square expo prime
    expo = (bnHalve ∘ bnHalve) $ (prime + 1)

#ifdef __HASTE__
bnSqrtModPAsync ∷ Bn → Bn → (Bn → IO ()) → IO ()
bnSqrtModPAsync square prime cont = bnPowerModAsync square expo prime cont
    where
    expo = (bnHalve ∘ bnHalve) $ (prime + 1)
#endif

-- -------------------------------------------------------------------------- --
-- * Keys

newtype SecretKey = SecretKey { unSk ∷ EcScalar }
    deriving (Show, Eq, Ord)

deriving instance Code64 Bn ⇒ Code64 SecretKey
deriving instance Code16 Bn ⇒ Code16 SecretKey

instance Bytes SecretKey where
    type ByteArrayImpl SecretKey = BackendByteArray
    toBytes = toBytes ∘ unSk
    fromBytes = fmap SecretKey ∘ fromBytes

instance BytesL SecretKey where
    type ByteLengthL SecretKey = SecretKeyLength
    toBytesL (SecretKey n) = ecScalarToBytesL n
    fromBytesL = fmap SecretKey ∘ fromBytes ∘ toBytes

newtype PublicKey = PublicKey { unPk ∷ EcPoint }
    deriving (Show, Eq, Code64, Code16)

-- | This instance of 'Ord' for 'PublicKey' does not
-- represent any topological properties. It is meant
-- primarily for data structures like binary search
-- trees.
instance Ord PublicKey where
    compare (PublicKey a) (PublicKey b) = compare (ecX a, ecY a) (ecX b, ecY b)

-- | We support two different encodings:
--
-- 1. the normal compresssed encoding as generated by the 'ToJSON' instance
--    of 'PublicKey'.
--
-- 2. an uncomporessed encoding. The uncompressed encoding consists of the
--    concatenation of the affine x and y conordinates byte serialization.
--
-- The length of the input determines which encoding is used.
--
instance Bytes PublicKey where
    type ByteArrayImpl PublicKey = BackendByteArray
    toBytes = toBytes ∘ unPk
    fromBytes bytes = PublicKey <$>
        (fromBytes bytes <|>
            (ecPoint
                <$> fromBytes (take ecScalarLength bytes)
                <*> fromBytes (drop ecScalarLength bytes)))

-- | We support two different encodings:
--
-- 1. the normal compresssed encoding as generated by the 'ToJSON' instance
--    of 'PublicKey'.
--
-- 2. an uncomporessed encoding. The uncompressed encoding consists of the
--    concatenation of the affine x and y conordinates byte serialization.
--
-- The length of the input determines which encoding is used.
--
instance BytesL PublicKey where
    type ByteLengthL PublicKey = PublicKeyLength
    toBytesL (PublicKey point) = toBytesL point
    fromBytesL bytesL = PublicKey <$>
        (fromBytesL bytesL <|>
            (ecPoint
                <$> ecFieldFromBytesL (takeL bytesL)
                <*> ecFieldFromBytesL (takeEndL bytesL)))

type PublicKeyLength = EcPointLength

publicKeyLength ∷ Int
publicKeyLength = ecPointLength

type SecretKeyLength = EcScalarLength

secretKeyLength ∷ Int
secretKeyLength = curveFieldLength

data KeyPair = KeyPair
    { jEcKeyPairPk ∷ PublicKey
    , jEcKeyPairSk ∷ SecretKey
    }

-- | Create EC key pair
--
generateKeyPair ∷ MonadIO μ ⇒ μ KeyPair
generateKeyPair = liftIO $ do
    secBn ← ecScalarRandom
    let pkPoint =  ecPointMul curveG secBn
    return $ KeyPair (PublicKey pkPoint) (SecretKey secBn)

-- | Basic Diffie-Hellman
--
dh ∷ SecretKey → PublicKey → EcPoint
dh (SecretKey sec) (PublicKey pub) = ecPointMul pub sec

-- | Basic Diffie-Hellman
--
-- Returns the affine x-coordinate of the resulting point
--
dhSecret ∷ SecretKey → PublicKey → EcScalar
dhSecret sk pk = ecScalar ∘ ecX $ dh sk pk

getPk ∷ SecretKey → PublicKey
getPk sec = PublicKey $ dh sec (PublicKey curveG)

-- -------------------------------------------------------------------------- --
-- Parser

pPk ∷ (BytesL PublicKey) ⇒ Parser (ByteArrayImpl PublicKey) PublicKey
pPk = pTakeBytesL <?> "pPk"

pSk ∷ (BytesL SecretKey) ⇒ Parser (ByteArrayImpl SecretKey) SecretKey
pSk = pTakeBytesL <?> "pSk"

pScalar ∷ (BytesL EcScalar) ⇒ Parser (ByteArrayImpl EcScalar) EcScalar
pScalar = pTakeBytesL <?> "pScalar"

pEcPoint ∷ (BytesL EcPoint) ⇒ Parser (ByteArrayImpl EcPoint) EcPoint
pEcPoint = pTakeBytesL <?> "pEcPoint"

