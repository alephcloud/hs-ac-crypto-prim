-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}

-- | An implementation of basic EC primitives for EC cryptography.
--
-- This implementation does only depend on an Bn implementation.
--
-- Serialization is provided in a different module for two reasons:
--
-- 1. A dependency on 'ByteArray' is avoided and
--
-- 2. A alternate EC implementations may provide optimized versions of
--    the primitives in the module but yet to use the more high-level
--    EC algorithms that are used for serialization and exported in
--    that other module.
--
-- Currently the serialization code and the associated algorithms are
-- located in "PC.Crypto.Prim". They will be moved into a separate module
-- soon.
--
module PC.Crypto.Prim.Ecc.Native
(
-- * Elliptic Curve Mathemtics
  EcCurve
, curve
, curveG
, curveR
, curveP
, curveB
, curveFieldLength
, CurveFieldLength
, EcFieldLength
, ecFieldLength

-- * EcPoint
, EcPoint
, ecPoint
, ecX
, ecY
, ecPointMul
, ecPointMul2
, ecPointAdd
, ecIdentity

-- * Scalar Values of the cyclic subgroup generated by 'curveG' of order 'curveR'
, EcScalar
, ecScalarBn
, ecScalar
, ecScalarDiv
) where

import Prelude.Unicode
import PC.Crypto.Prim.Bn
-- import PC.Crypto.Prim.ByteArrayL (N66)

-- -------------------------------------------------------------------------- --
-- * Prime order elleptic curve

-- | We standardize on p512
--
-- The curve can be change at compile time by making this a CPP macro.
--
curve ∷ EcCurve
curve = p521

-- | Prime order elliptic standard curve
--
-- Parameters:
--
-- Let E: @y^2 = x^3 + a * x + b@
--
-- * curveP: prime field of order p
--
-- * curveA: the parameter @a@ in equation E
--
-- * curveB: the parameter @b@ in equation E
--
-- * curveG: generator for a cyclic subgroup of the Abelian group @E(F_{curveP})@.
--
-- * curveR: the order of G (the smallest non-negative i such that i*G is the point of infinity)
--
-- For prime curves NIST and Certicom <http://www.secg.org/download/aid-386/sec2_final.pdf> curves
-- the cofactor h = @E(F_{curveP}) / curveR@ is 1. Therefor it holds that
--
-- > curveR = E(F_{curveP})
--
-- Hence for every @i@ in @F_{curveP}@ the point @E(i)@ is in the cyclic subgroup of @G@.
--
data EcCurve = EcCurve
    { curveP_ ∷ Bn -- ^ the curve prime @p_521 = 2^251 - 1@
    , curveA_ ∷ Bn -- ^ a parameter in curve equation @p_521 - 3@
    , curveB_ ∷ Bn -- ^ b parameter in curve equation
    , curveG_ ∷ EcPoint -- ^ base point G of the curve group
    , curveR_ ∷ Bn -- ^ the order of G (the order of the elliptic curve group generated by G)
    }

-- | Standard curve p-521 (see NIST or Certicom <http://www.secg.org/download/aid-386/sec2_final.pdf>)
--
p521 ∷ EcCurve
p521 = EcCurve
    { curveP_ = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    , curveA_ = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
    , curveB_ = 0x00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
    , curveG_ = ecPoint
               0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
               0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
    , curveR_ = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    }

curveP ∷ Bn
curveP = curveP_ curve

curveA ∷ Bn
curveA = curveA_ curve

curveB ∷ Bn
curveB = curveB_ curve

curveG ∷ EcPoint
curveG = curveG_ curve

curveR ∷ Bn
curveR = curveR_ curve

-- FIXME
type CurveFieldLength = 66
type EcFieldLength = CurveFieldLength

curveFieldLength ∷ Int
curveFieldLength = bnLength curveR

ecFieldLength ∷ Int
ecFieldLength = curveFieldLength

-- -------------------------------------------------------------------------- --
-- * Scalar Values

-- | Scalar for the cyclic curve group generated by G
--
-- The the group is of order 'curveR' the 'Num' instance should
-- implement arithmetic modulo 'curveR'.
--
-- In particular secret keys are scalar of the cyclic curve group.
--
-- Affine coordinates of a point on the curve are /not/ scalars
-- but value of the curve field.
--
-- FIXME the derived NUM instance is probably not what we want!
--
-- We shall use it in the definition of EcPoint?
--
--
newtype EcScalar = EcScalar { ecScalarBn ∷ Bn }
    deriving (Eq, Ord, Show, Integral, Real, Enum)

ecScalar ∷ Bn → EcScalar
ecScalar i = EcScalar (i `mod` curveR)

ecScalarDiv ∷ Bn → Bn → Bn
ecScalarDiv a b = (a * bnInverseMod b curveP) `mod` curveP

instance Num EcScalar where
    (EcScalar a) + (EcScalar b) = EcScalar $ (a + b) `mod` curveR
    (EcScalar a) - (EcScalar b) = EcScalar $ (a - b) `mod` curveR
    (EcScalar a) * (EcScalar b) = EcScalar $ (a * b) `mod` curveR
    abs = id
    signum a = if a ≡ 0 then 0 else 1
    fromInteger = ecScalar ∘ fromInteger

-- -------------------------------------------------------------------------- --
-- Prime order elleptic curve

-- | A point on an elliptic curve
--
-- We do not store the curve, since this module assumes static default curve.
--
data EcPoint
    = EcIdentity
    | EcPoint
        { ecX ∷ !Bn
        , ecY ∷ !Bn
        }
    deriving Eq

ecIdentity ∷ EcPoint
ecIdentity = EcIdentity

ecPoint ∷ Bn → Bn → EcPoint
ecPoint x y
    | y ^ (2 ∷ Bn) - x ^ (3 ∷ Bn) - curveA * x ^ (2 ∷ Bn) - curveB ≡ 0 `mod` curveP = error "Invalid point"
    | otherwise = EcPoint x y

-- | b.a
--
-- FIXME reorder arguments
--
ecPointMul ∷ EcPoint → EcScalar → EcPoint
ecPointMul a b
    | a ≡ EcIdentity || b ≡ 0 = EcIdentity
    | odd  b = (a `ecPointMul` (b - 1)) `ecPointAdd` a
    | even b = ecPointDouble (a `ecPointMul` (b `div` 2))
    | otherwise = error "must not happend"

ecPointDouble ∷ EcPoint → EcPoint
ecPointDouble a = a `ecPointAdd` a

-- | b.a + c.d
--
-- FIXME reorder arguments
--
ecPointMul2 ∷ EcPoint → EcScalar → EcScalar → EcPoint → EcPoint
ecPointMul2 a b c d
    | a ≡ EcIdentity || b ≡ 0 = d `ecPointMul` c
    | d ≡ EcIdentity || c ≡ 0 = a `ecPointMul` b
    | odd b && even c = a `ecPointAdd` ecPointMul2 a (b - 1) c d
    | even b && odd c = d `ecPointAdd` ecPointMul2 a b (c - 1) d
    | odd b && odd c = a `ecPointAdd` d `ecPointAdd` (ecPointMul2 a (b - 1) (c - 1) d)
    | even b && even c = ecPointDouble $ ecPointMul2 a (b `div` 2) (c `div` 2) d
    | otherwise = error "must not happen"

ecPointAdd ∷ EcPoint → EcPoint → EcPoint
ecPointAdd EcIdentity b = b
ecPointAdd a EcIdentity = a
ecPointAdd (EcPoint x0 y0) (EcPoint x1 y1)
    | ((x0 - x1) `mod` p ≡ 0) && ((y0 + y1) `mod` p ≡ 0) = EcIdentity
    | otherwise = EcPoint x y
    where
    p = curveP
    a = curveA
    m | ((x0 - x1) `mod` p ≡ 0) && ((y0 - y1) `mod` p ≡ 0) = (3 * x0^(2 ∷ Bn) + a) * bnInverseMod (2 * y0) p
      | otherwise = (y1 - y0) * bnInverseMod (x1 - x0) p
    x = (m^(2 ∷ Bn) - x0 - x1) `mod` p
    y = (m * (x0 - x) - y0) `mod` p
