{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | Static length byte arrays
--
module TWC.Crypto.ByteArrayL
( ByteArrayL(..)
, BackendByteArrayL
, lengthL
, emptyL
, takeL
, takeEndL
, dropL
, dropEndL
, splitL
, concatL
, randomBytesL

-- ** Serialization
, BytesL(..)

-- ** type level numbers
, Nat
, Add
, Mul
, N0
, N1
, N2
, N4
, N16
, N32
, N64
, N66
, toInt
) where

import Control.Applicative hiding (empty)
import Control.Arrow
import Control.Monad

import Data.Monoid.Unicode

import Prelude hiding (splitAt, length, take, drop)
import Prelude.Unicode

import TWC.Crypto.ByteArray

import TypeLevel.Number.Nat
import TypeLevel.Number.Nat.Num

type BackendByteArrayL = ByteArrayL BackendByteArray

-- -------------------------------------------------------------------------- --

newtype ByteArrayL α n = ByteArrayL α
    deriving (Eq, Ord, Show, Code16, Code64)

instance (Nat n, ByteArray α) ⇒ Bytes (ByteArrayL α n) where
    type ByteArrayImpl (ByteArrayL α n) = α
    toBytes (ByteArrayL bytes) = bytes
    fromBytes a = ByteArrayL <$> (check =<< Right a)
        where
        e = toInt (undefined ∷ n) ∷ Int
        check x = do
            let l = length x
            if l ≡ toInt (undefined ∷ n)
                then Right x
                else Left $ "wrong length: expected " ⊕ show e ⊕ " got " ⊕ show l

    -- Allows specialization elsewhere
    {-# INLINEABLE toBytes #-}
    {-# INLINEABLE fromBytes #-}

{-
instance (Nat n, Code64 α, ByteArray α) ⇒ Code64 (ByteArrayL α n) where
    to64 (ByteArrayL a) = to64 a
    from64 = fromBytes <=< (from64 ∷ String → Either String α)

    {-# INLINEABLE to64 #-}
    {-# INLINEABLE from64 #-}

instance (Nat n, Code16 α, ByteArray α) ⇒ Code16 (ByteArrayL α n) where
    to16 (ByteArrayL a) = to16 a
    from16 = fromBytes <=< (from16 ∷ String → Either String α)

    {-# INLINEABLE to16 #-}
    {-# INLINEABLE from16 #-}
-}

lengthL
    ∷ ∀ β n . Nat n
    ⇒ ByteArrayL β n
    → Int
lengthL _ = toInt (undefined ∷ n)
{-# INLINEABLE lengthL #-}

emptyL ∷ ByteArray β ⇒ ByteArrayL β N0
emptyL = ByteArrayL empty
{-# INLINABLE emptyL #-}

randomBytesL
    ∷ ∀ β n . (ByteArray β, Nat n)
    ⇒ IO (ByteArrayL β n)
randomBytesL = ByteArrayL <$> randomBytes (toInt (undefined ∷ n))
{-# INLINABLE randomBytesL #-}

dropL
    ∷ ∀ β m n i . (ByteArray β, Nat m, Nat n, Nat i, LesserEq i m, Sub m i ~ n)
    ⇒ i
    → ByteArrayL β m
    → ByteArrayL β n
dropL i (ByteArrayL a) = ByteArrayL $ drop (toInt (undefined ∷ i)) a
    where
    _n ∷ n
    _n = subN (undefined ∷ m) i
{-# INLINEABLE dropL #-}

dropEndL
    ∷ ∀ β m n i . (ByteArray β, Nat i, Nat m, LesserEq i m, Sub m i ~ n)
    ⇒ i
    → ByteArrayL β m
    → ByteArrayL β n
dropEndL i (ByteArrayL a) = ByteArrayL $ dropEnd (toInt (undefined ∷ i)) a
    where
    _n ∷ n
    _n = subN (undefined ∷ m) i
{-# INLINEABLE dropEndL #-}

takeL
    ∷ ∀ β m n . (ByteArray β, Nat m, Nat n, LesserEq n m)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
takeL (ByteArrayL a) = ByteArrayL $ take (toInt (undefined ∷ n)) a
{-# INLINEABLE takeL #-}

takeEndL
    ∷ ∀ β m n . (ByteArray β, Nat m, Nat n, LesserEq n m)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
takeEndL (ByteArrayL a) = ByteArrayL $ takeEnd (toInt (undefined ∷ n)) a
{-# INLINEABLE takeEndL #-}

splitL
    ∷ ∀ β m n o . (ByteArray β, Nat m, Nat n, Nat o, LesserEq n m, Sub m n ~ o)
    ⇒ ByteArrayL β m
    → (ByteArrayL β n, ByteArrayL β o)
splitL (ByteArrayL a) = (ByteArrayL *** ByteArrayL) $ splitAt (toInt (undefined ∷ n)) a
    where
    _o ∷ o
    _o = subN (undefined ∷ m) (undefined ∷ n)
{-# INLINABLE splitL #-}

concatL
    ∷ ∀ β m n x . (ByteArray β, Nat m, Nat n, Add m n ~ x)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
    → ByteArrayL β x
concatL (ByteArrayL a) (ByteArrayL b) = ByteArrayL $ a ⊕ b
    where
    _x ∷ x
    _x = addN (undefined ∷ m) (undefined ∷ n)
{-# INLINABLE concatL #-}

type N32 = Mul N4 N8
type N16 = Mul N2 N8
type N64 = Mul N8 N8
type N66 = Add N2 N64

class (Bytes α, Nat (ByteLengthL α)) ⇒ BytesL α where
    type ByteLengthL α
    toBytesL ∷ α → ByteArrayL (ByteArrayImpl α) (ByteLengthL α)
    fromBytesL ∷ ByteArrayL (ByteArrayImpl α) (ByteLengthL α) → Either String α

instance (ByteArray α, Nat n) ⇒ BytesL (ByteArrayL α n) where
    type ByteLengthL (ByteArrayL α n) = n
    toBytesL = id
    fromBytesL = Right

    {-# INLINABLE toBytesL #-}
    {-# INLINABLE fromBytesL #-}

-- TODO:
{-# SPECIALIZE lengthL ∷ ∀ n . Nat n ⇒ ByteArrayL BackendByteArray n → Int #-}
{-# SPECIALIZE emptyL ∷ ByteArrayL BackendByteArray N0 #-}
-- NOTE SPECIALIZE should be RULES now (vhanquez)

{-
newtype ByteArrayL (n ∷ Nat) = ByteArrayL ByteArray
    deriving (Bytes, Code16, Code64, Eq, Show)

lengthL ∷ ∀ n . (SingI n) ⇒ ByteArrayL n → Int
lengthL _ = fromIntegral (fromSing (sing ∷ Sing (n ∷ Nat)) ∷ Integer)

emptyL ∷ ByteArrayL 0
emptyL = ByteArrayL empty

randomBytesL ∷ ∀ n . (SingI n) ⇒ IO (ByteArrayL n)
randomBytesL = ByteArrayL <$> randomBytes (fromIntegral (fromSing (sing ∷ Sing n)))

dropL ∷ ∀ m n i . ((n + i) ~ m) ⇒ Sing i → ByteArrayL (n ∷ Nat) → ByteArrayL (m ∷ Nat)
dropL i (ByteArrayL a) = ByteArrayL $ drop (fromIntegral (fromSing i)) a

takeL ∷ ∀ n i . (i <= n) ⇒ Sing i → ByteArrayL (n ∷ Nat) → ByteArrayL (i ∷ Nat)
takeL i (ByteArrayL a) = ByteArrayL $ take (fromIntegral (fromSing i)) a

dropEndL ∷ ∀ m n i . ((n + i) ~ m) ⇒ Sing i → ByteArrayL (n ∷ Nat) → ByteArrayL (m ∷ Nat)
dropEndL i (ByteArrayL a) = ByteArrayL $ dropEnd (fromIntegral (fromSing i)) a

takeEndL ∷ ∀ n i . (n <= i) ⇒ Sing i → ByteArrayL (n ∷ Nat) → ByteArrayL (i ∷ Nat)
takeEndL i (ByteArrayL a) = ByteArrayL $ takeEnd (fromIntegral (fromSing i)) a

splitAtL ∷ ∀ m n i . ((n + i) ~ m) ⇒ Sing i → ByteArrayL (n ∷ Nat) → (ByteArrayL (i ∷ Nat), ByteArrayL m)
splitAtL i (ByteArrayL a) = (ByteArrayL *** ByteArrayL) $ splitAt (fromIntegral (fromSing i)) a

splitAtEndL ∷ ∀ m n i . ((n + i) ~ m) ⇒ Sing i → ByteArrayL (n ∷ Nat) → (ByteArrayL (m ∷ Nat), ByteArrayL i)
splitAtEndL i (ByteArrayL a) = (ByteArrayL *** ByteArrayL) $ splitAtEnd (fromIntegral (fromSing i)) a

concatL ∷ ∀ m n o . (SingI n, SingI m, SingI (n + m), (n + m) ~ o) ⇒ ByteArrayL m → ByteArrayL n → ByteArrayL o
concatL (ByteArrayL a) (ByteArrayL b) = ByteArrayL $ a ⊕ b

-- test
empty2 ∷ ByteArrayL 0
empty2 = emptyL `concatL` emptyL
-}

{-
-- Static tests
empty2 ∷ (ByteArray β) ⇒ ByteArrayL β N0
empty2 = emptyL `concatL` emptyL
-}

