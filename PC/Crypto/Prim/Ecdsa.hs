-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module PC.Crypto.Prim.Ecdsa
( EcdsaSignature(..)
, sign
, signWith
, verify
) where

import Control.Applicative
import Control.DeepSeq (NFData)
import Control.Monad.IO.Class

import Data.Byteable (constEqBytes)
import Data.Monoid
import Data.Proxy
import qualified Data.ByteString as B (length, splitAt)

import GHC.Generics
import GHC.TypeLits

import Prelude hiding (take, drop)

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Bn
import PC.Crypto.Prim.Sha

import PC.Bytes.Utils
import PC.Crypto.Prim.Ecc

-- -------------------------------------------------------------------------- --
-- * ECDSA

data EcdsaSignature curve = EcdsaSignature
    { ecdsa_r :: !(EcScalar curve)
    , ecdsa_s :: !(EcScalar curve)
    } deriving (Show,Generic)

instance NFData (EcdsaSignature curve)

instance EcCurve curve => Eq (EcdsaSignature curve) where
    (EcdsaSignature r1 s1) == (EcdsaSignature r2 s2) = (toInt rEq + toInt sEq) == 2
      where rEq = toBytes r1 `constEqBytes` toBytes r2
            sEq = toBytes s1 `constEqBytes` toBytes s2
            toInt :: Bool -> Int
            toInt False = 0
            toInt True  = 1

instance EcCurve curve => Bytes (EcdsaSignature curve) where
    toBytes (EcdsaSignature r s) = toBytes r `mappend` toBytes s
    fromBytes bs
        | odd len   = Left "invalid size ECDSA signature. not even"
        | otherwise = do let (r_bs, s_bs) = B.splitAt (len `div` 2) bs
                         r <- fromBytes r_bs
                         s <- fromBytes s_bs
                         if r == 0 || s == 0
                            then Left "Invalid ECDSA signature. r or s constraint invalid."
                            else Right $ EcdsaSignature { ecdsa_r = r, ecdsa_s = s }
      where len = B.length bs

sign :: (EcCurve curve, MonadIO io)
     => SecretKey curve           -- ^ secret key to sign with
     -> BackendByteArray          -- ^ data to sign
     -> io (EcdsaSignature curve)
sign sk content = do
    k <- ecScalarRandomNonZero
    return $ signWith sk content k

signWith :: EcCurve curve
         => SecretKey curve
         -> BackendByteArray
         -> EcScalar curve
         -> EcdsaSignature curve
signWith (SecretKey sk) content k =
    let r = (ecX $ ecPointGen k) `mod` curve_R -- we should assert that r /= 0. Won't happen...
        s = bnMulMod (sh + (r * skBn)) (bnInverseMod k_bn curve_R) curve_R
     in EcdsaSignature { ecdsa_r = ecScalar r, ecdsa_s = ecScalar s }
  where
    sh = unsafeFromBytes . padLeft 0 ecFieldLength . take ecFieldLength . toBytes $ sha512Hash content
    skBn = getEcScalarBn $ sk
    k_bn = getEcScalarBn k

    curve   = getScalarCurve sk
    curve_R = curveR curve
    ecFieldLength = curveFieldLength curve

verify :: EcCurve curve
       => PublicKey curve
       -> BackendByteArray
       -> EcdsaSignature curve
       -> Bool
verify qA content sig =
    toBytes r2 `constEqBytes` toBytes (ecdsa_r sig)
  where
    r2 = ecXscalar $ ecPointMul2 curve_G u1 u2 (unPk qA)
    u2 = ecdsa_r sig * w
    u1 = z * w
    w = ecScalarInverse (ecdsa_s sig)
    z = either error id . fromBytes . padLeft 0 ecFieldLength . take ecFieldLength . toBytes $ sha512Hash content

    ecFieldLength = curveFieldLength curve
    curve_R       = curveR curve
    curve_G       = curveG curve
    curve         = getPointCurve (unPk qA)
