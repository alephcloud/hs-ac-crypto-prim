-- ------------------------------------------------------ --
-- Copyright © 2013, 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ConstraintKinds #-}

-- | Static length byte arrays
--
module PC.Crypto.Prim.ByteArrayL
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
, toInt
, type (≤)
) where

import Control.Applicative hiding (empty)
import Control.Arrow
import Control.Monad

import Data.Monoid.Unicode
import Data.Proxy

import Prelude hiding (splitAt, length, take, drop)
import Prelude.Unicode

import PC.Crypto.Prim.ByteArray

import GHC.TypeLits

type BackendByteArrayL = ByteArrayL BackendByteArray

-- -------------------------------------------------------------------------- --

newtype ByteArrayL α (n ∷ Nat) = ByteArrayL α
    deriving (Eq, Ord, Show, Code16, Code64)

instance (ByteArray α, KnownNat n) ⇒ Bytes (ByteArrayL α n) where
    type ByteArrayImpl (ByteArrayL α n) = α
    toBytes (ByteArrayL bytes) = bytes
    fromBytes a = ByteArrayL <$> (check =<< Right a)
        where
        e = toInt (Proxy ∷ Proxy n) ∷ Int
        check x = do
            let l = length x
            if l ≡ toInt (Proxy ∷ Proxy n)
                then Right x
                else Left $ "wrong length: expected " ⊕ show e ⊕ " got " ⊕ show l

    -- Allows specialization elsewhere
    {-# INLINEABLE toBytes #-}
    {-# INLINEABLE fromBytes #-}

toInt ∷ ∀ ν proxy α. (KnownNat ν, Integral α) => proxy ν -> α
toInt = fromIntegral ∘ natVal

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

type (≤) α β = (<=) α β

lengthL
    ∷ ∀ β n . KnownNat n
    ⇒ ByteArrayL β n
    → Int
lengthL _ = toInt (Proxy ∷ Proxy n)
{-# INLINEABLE lengthL #-}

emptyL ∷ ByteArray β ⇒ ByteArrayL β 0
emptyL = ByteArrayL empty
{-# INLINABLE emptyL #-}

randomBytesL
    ∷ ∀ β ν . (KnownNat ν, ByteArray β)
    ⇒ IO (ByteArrayL β ν)
randomBytesL = ByteArrayL <$> randomBytes (toInt (Proxy ∷ Proxy ν))
{-# INLINABLE randomBytesL #-}

dropL
    ∷ ∀ β i m n proxy. (KnownNat i, ByteArray β, i ≤ m, (m - i) ~ n)
    ⇒ proxy i
    → ByteArrayL β m
    → ByteArrayL β n
dropL i (ByteArrayL a) = ByteArrayL $ drop (toInt i) a
{-# INLINEABLE dropL #-}

dropEndL
    ∷ ∀ β i m n proxy. (KnownNat i, ByteArray β, i ≤ m, (m - i) ~ n)
    ⇒ proxy i
    → ByteArrayL β m
    → ByteArrayL β n
dropEndL i (ByteArrayL a) = ByteArrayL $ dropEnd (toInt i) a
{-# INLINEABLE dropEndL #-}

takeL
    ∷ ∀ β m n. (KnownNat n, ByteArray β, n ≤ m)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
takeL (ByteArrayL a) = ByteArrayL $ take (toInt (Proxy ∷ Proxy n)) a
{-# INLINEABLE takeL #-}

takeEndL
    ∷ ∀ β m n. (KnownNat n, ByteArray β, n ≤ m)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
takeEndL (ByteArrayL a) = ByteArrayL $ takeEnd (toInt (Proxy ∷ Proxy n)) a
{-# INLINEABLE takeEndL #-}

splitL
    ∷ ∀ β m n o. (KnownNat n, ByteArray β, n ≤ m, (m - n) ~ o)
    ⇒ ByteArrayL β m
    → (ByteArrayL β n, ByteArrayL β o)
splitL (ByteArrayL a) = (ByteArrayL *** ByteArrayL) $ splitAt (toInt (Proxy ∷ Proxy n)) a
{-# INLINABLE splitL #-}

concatL
    ∷ (ByteArray β, (m + n) ~ x)
    ⇒ ByteArrayL β m
    → ByteArrayL β n
    → ByteArrayL β x
concatL (ByteArrayL a) (ByteArrayL b) = ByteArrayL $ a ⊕ b
{-# INLINABLE concatL #-}

class (Bytes α) ⇒ BytesL α where
    type ByteLengthL α ∷ Nat
    toBytesL ∷ α → ByteArrayL (ByteArrayImpl α) (ByteLengthL α)
    fromBytesL ∷ ByteArrayL (ByteArrayImpl α) (ByteLengthL α) → Either String α

instance (KnownNat n, ByteArray α) ⇒ BytesL (ByteArrayL α n) where
    type ByteLengthL (ByteArrayL α n) = n
    toBytesL = id
    fromBytesL = Right

    {-# INLINABLE toBytesL #-}
    {-# INLINABLE fromBytesL #-}

-- TODO:
{-# SPECIALIZE lengthL ∷ ∀ n . KnownNat n ⇒ ByteArrayL BackendByteArray n → Int #-}
{-# SPECIALIZE emptyL ∷ ByteArrayL BackendByteArray 0 #-}
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

