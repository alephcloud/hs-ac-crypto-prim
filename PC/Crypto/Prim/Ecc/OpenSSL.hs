-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Ecc.OpenSSL
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
-- Module      : PC.Crypto.Prim.Ecc.OpenSSL
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.Ecc.OpenSSL
(
-- * Elliptic Curve Mathematics
  EcCurve(..)
, P521
, p521
, P256
, p256

-- * EcPoint
, EcPoint
, ecPoint
, ecX
, ecXscalar
, ecY
, ecPointMul
, ecPointMulAddGeneratorMul
, ecPointGen
, ecPointAdd
, ecIdentity

-- * Scalar Values of the cyclic subgroup generated by 'curveG' of order 'curveR'
, EcScalar
, getEcScalarBn
, ecScalar
, ecScalarInverse

-- * polymorphic helper point and scalar to curve
, getScalarCurve
, getPointCurve
) where

import Control.Applicative
import Control.DeepSeq (NFData)
import Data.Proxy
import PC.Bytes.ByteArray
import PC.Crypto.Prim.Ecc.OpenSSLBind
import PC.Crypto.Prim.Bn

newtype EcPoint curve = EcPoint Point
    deriving (NFData)

type EcGroup = Group

class EcCurve curve where
    curveFromProxy    :: Proxy curve -> curve
    curveGroup        :: curve -> EcGroup
    curveA            :: curve -> Bn
    curveB            :: curve -> Bn
    curveP            :: curve -> Bn
    curveR            :: curve -> Bn
    curveG            :: curve -> EcPoint curve
    curveFieldLength  :: curve -> Int
    curvePointToBin   :: curve -> EcPoint curve -> BackendByteArray
    curvePointFromBin :: curve -> BackendByteArray -> Either String (EcPoint curve)

instance EcCurve curve => Eq (EcPoint curve) where
    ecp@(EcPoint a) == (EcPoint b) = pointEq (getPointGroup ecp) a b

getGroup name oid =
       maybe (error $ "cannot get openssl curve " ++ name) id
     $ groupFromCurveName
     $ maybe (error $ "cannot convert text to nid " ++ name) id
     $ txt2Nid oid

newtype P521 = P521 Group
    deriving (NFData)

p521 = P521 $ getGroup "p521" "1.3.132.0.35"

instance EcCurve P521 where
    curveFromProxy _ = p521
    curveGroup (P521 group) = group
    curveP (P521 g) = let (p,_,_) = groupGetCurveGFp g in p
    curveA (P521 g) = let (_,a,_) = groupGetCurveGFp g in a
    curveB (P521 g) = let (_,_,b) = groupGetCurveGFp g in b
    curveG (P521 g) = EcPoint $ groupGetGenerator g
    curveR (P521 g) = groupGetOrder g

    curveFieldLength (P521 _) = 66
    curvePointToBin (P521 g) (EcPoint point) = pointToOct g point PointConversion_Compressed
    curvePointFromBin (P521 g) bs = EcPoint <$> octToPoint g bs

newtype P256 = P256 Group
    deriving (NFData)

p256 = P256 $ getGroup "p256" "1.2.840.10045.3.1.7"

instance EcCurve P256 where
    curveFromProxy _ = p256
    curveGroup (P256 group) = group
    curveP (P256 g) = let (p,_,_) = groupGetCurveGFp g in p
    curveA (P256 g) = let (_,a,_) = groupGetCurveGFp g in a
    curveB (P256 g) = let (_,_,b) = groupGetCurveGFp g in b
    curveG (P256 g) = EcPoint $ groupGetGenerator g
    curveR (P256 g) = groupGetOrder g

    curveFieldLength (P256 _) = 32
    curvePointToBin (P256 g) (EcPoint point) = pointToOct g point PointConversion_Compressed
    curvePointFromBin (P256 g) bs = EcPoint <$> octToPoint g bs


getScalarGroup :: EcCurve curve => EcScalar curve -> EcGroup
getScalarGroup = curveGroup . getScalarCurve

getScalarCurve :: EcCurve curve => EcScalar curve -> curve
getScalarCurve = getCurve Proxy
  where getCurve :: EcCurve curve => Proxy curve -> EcScalar curve -> curve
        getCurve proxy _ = curveFromProxy proxy

getPointGroup :: EcCurve curve => EcPoint curve -> EcGroup
getPointGroup = curveGroup . getPointCurve

getPointCurve :: EcCurve curve => EcPoint curve -> curve
getPointCurve = getCurve Proxy
  where getCurve :: EcCurve curve => Proxy curve -> EcPoint curve -> curve
        getCurve proxy _ = curveFromProxy proxy

newtype EcScalar curve = EcScalar { getEcScalarBn :: Bn }
    deriving (Eq, Ord, Show, Integral, Real, Enum, NFData)

ecScalar :: EcCurve curve => Bn -> EcScalar curve
ecScalar i = modCurve Proxy
  where modCurve :: EcCurve curve => Proxy curve -> EcScalar curve
        modCurve proxy = EcScalar (i `mod` curveR (curveFromProxy proxy))

instance EcCurve curve => Num (EcScalar curve) where
    sa@(EcScalar a) + (EcScalar b) = EcScalar $ (a + b) `mod` curveR (getScalarCurve sa)
    sa@(EcScalar a) - (EcScalar b) = EcScalar $ (a - b) `mod` curveR (getScalarCurve sa)
    sa@(EcScalar a) * (EcScalar b) = EcScalar $ (a * b) `mod` curveR (getScalarCurve sa)
    abs = id
    signum a = if a == 0 then 0 else 1
    fromInteger = ecScalar . fromInteger

ecX :: EcCurve curve => EcPoint curve -> Bn
ecX ecp@(EcPoint p) = fst $ pointToAffineGFp (getPointGroup ecp) p

ecXscalar :: EcCurve curve => EcPoint curve -> EcScalar curve
ecXscalar ecp@(EcPoint p) = ecScalar $ fst $ pointToAffineGFp (getPointGroup ecp) p

ecY :: EcCurve curve => EcPoint curve -> Bn
ecY ecp@(EcPoint p) = snd $ pointToAffineGFp (getPointGroup ecp) p

ecIdentity :: EcCurve curve => EcPoint curve
ecIdentity = getInfinity Proxy
  where getInfinity :: EcCurve curve => Proxy curve -> EcPoint curve
        getInfinity proxy = EcPoint $ pointInfinity (curveGroup $ curveFromProxy proxy)

ecIsIdentity :: EcCurve curve => EcPoint curve -> Bool
ecIsIdentity ecp@(EcPoint p) = pointIsAtInfinity (getPointGroup ecp) p

ecPoint :: EcCurve curve => Bn -> Bn -> EcPoint curve
ecPoint x y = mkPoint Proxy (x,y)
  where mkPoint :: EcCurve curve => Proxy curve -> (Bn, Bn) -> EcPoint curve
        mkPoint proxy coord = EcPoint $ pointFromAffineGFp (curveGroup $ curveFromProxy proxy) coord

-- | b.a
--
-- FIXME reorder arguments
--
ecPointMul :: EcCurve curve => EcPoint curve -> EcScalar curve -> EcPoint curve
ecPointMul p@(EcPoint a) (EcScalar b) = EcPoint $ pointMul (getPointGroup p) a b

-- | Lift to curve a secret. generator(curve) ^ sec
ecPointGen :: EcCurve curve => EcScalar curve -> EcPoint curve
ecPointGen = gen Proxy
  where gen :: EcCurve curve => Proxy curve -> EcScalar curve -> EcPoint curve
        gen proxy (EcScalar scalar) =
            let curve = curveFromProxy proxy
             in EcPoint $ pointGeneratorMul (curveGroup curve) scalar

ecPointDouble :: EcCurve curve => EcPoint curve -> EcPoint curve
ecPointDouble p@(EcPoint a) = EcPoint $ pointDbl (getPointGroup p) a

-- | compute generator * n + q * m
ecPointMulAddGeneratorMul :: EcCurve curve => EcScalar curve -> EcScalar curve -> EcPoint curve -> EcPoint curve
ecPointMulAddGeneratorMul (EcScalar n) (EcScalar m) q@(EcPoint q') =
    EcPoint $ pointMulWithGenerator (getPointGroup q) n q' m

ecPointAdd :: EcCurve curve => EcPoint curve -> EcPoint curve -> EcPoint curve
ecPointAdd p@(EcPoint a) (EcPoint b) = EcPoint $ pointAdd (getPointGroup p) a b

ecScalarInverse :: EcCurve curve => EcScalar curve -> EcScalar curve
ecScalarInverse s@(EcScalar n) = EcScalar $ bnInverseMod n (curveR (getScalarCurve s))
