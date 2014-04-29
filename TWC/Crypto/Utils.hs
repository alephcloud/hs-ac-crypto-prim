{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE CPP #-}

module TWC.Crypto.Utils
( unsafeFromBytes
, unsafeFromBytesL
, padLeft
, splitHalf
, splitHalfL
, HalfF
, HalfC
, (:+:)
, (%)

-- * Binary Parser
, Parser(..)
, (<?>)
, parse
, parse'
, eof
, isEof
, pEither
, pAssert
, pListL
, pTake
, pTakeAll
, pTakeExcept
, pTakeBytesL
, pTakeBytes
, pSha512_256
, pAesIV
, pAes256mac
) where

import Control.Applicative hiding (empty)
import Control.Arrow hiding (left, right)

import Data.Monoid.Unicode
import Data.Word (Word8)

import Prelude hiding (splitAt, length)
import Prelude.Unicode

import TWC.Crypto.ByteArray
import TWC.Crypto.ByteArrayL
import TWC.Crypto.Sha
import TWC.Crypto.Aes

import qualified TypeLevel.Number.Nat as N

-- -------------------------------------------------------------------------- --
-- * Utils

-- | Use this method only for 'fromBytes' conversions that are fully generic,
-- i.e. for unconstraint newtype wrappers or in places with strong
-- local code invariants. For instance:
--
-- > byteArray ← randomBytes 100
-- > let a = take 10 byteArray
-- > let typeWithExactly10bytesArray = unsafeFromBytes a
--
-- The only thing that possibly can go wrong here is a length mismatch
-- (which we currently don't check). Hence, if something goes wrong here
-- it's a bug in the code and throwing an asynchronous exception is fine.
--
-- FIXME Make this a type class and avoid the partial function!
--
unsafeFromBytes ∷ ∀ α . Bytes α ⇒ ByteArrayImpl α → α
unsafeFromBytes = either (\e → error $ "Failed to interpret bitArray. This is a bug in the code: " ⊕ e) id ∘ fromBytes

unsafeFromBytesL ∷ ∀ α . (BytesL α) ⇒ ByteArrayL (ByteArrayImpl α) (ByteLengthL α) → α
unsafeFromBytesL = either error id ∘ fromBytesL

-- | pad a ByteArray on the left
--
-- > length (padLeft a i b) ≡ i
--
padLeft ∷ ByteArray α ⇒ Word8 → Int → α → α
padLeft a i b
    | (length b) < i = fromList (replicate (i - length b) a) ⊕ b
    | otherwise = b

(%)
    ∷ (N.Nat n, N.Nat m, N.Nat o, N.Add n m ~ o)
    ⇒ BackendByteArrayL n
    → BackendByteArrayL m
    → BackendByteArrayL o
(%) = concatL

-- | For odd input length the first component of the result
-- is one byte shorter than the second component.
--
splitHalf
    ∷ BackendByteArray
    → (BackendByteArray, BackendByteArray)
splitHalf s = splitAt (length s `div` 2) s

-- | For odd input length the first component of the result
-- is one byte shorter than the second component.
--
splitHalfL
    ∷ ∀ n m0 m1 . (N.Nat n, N.Nat m0, N.Nat m1, N.LesserEq m0 n, m1 ~ N.Sub n m0, N.Add m0 m1 ~ n, m0 ~ HalfF n, m1 ~ HalfC n)
    ⇒ BackendByteArrayL n
    → (BackendByteArrayL m0, BackendByteArrayL m1)
splitHalfL n = splitL n

-- | HalfF n is floor(n/2)
--
type family HalfF n ∷ *
type instance HalfF N.Z = N.Z
type instance HalfF (N.O m) = m
type instance HalfF (N.I m) = m

-- | HalfF n is ceiling(n/2)
--
type family HalfC n ∷ *
type instance HalfC N.Z = N.Z
type instance HalfC (N.O m) = m
type instance HalfC (N.I m) = N.Add m N1

type (:+:) a b = Add a b

-- -------------------------------------------------------------------------- --
-- * A simple (yet) non-backtracking deterministic parser for 'ByteArray's

-- | A simple non-backtracking deterministic parser simple parser that is
-- generic with respect to the underlying ByteArray
--
-- The type-parameter is the underlying ByteArray implementation.
--
newtype Parser π α = Parser { unBAP ∷ π → (Either String α, π) }

pEither ∷ ∀ π α β . ByteArray π ⇒ (α → Either String β) → Parser π α → Parser π β
pEither f p = Parser $ \(a ∷ π) → case (unBAP p) a of
    (Right r, a') → case f r of
        Right r' → (Right r', a')
        Left e → (Left e, a)
    (Left e, _) → (Left e, a)

pAssert ∷ ByteArray π ⇒ String → (α → Bool) → Parser π α → Parser π α
pAssert msg f = pEither $ \a → if f a then Right a else Left msg

-- | Consumes remaining input into a list of
-- values parsed by the given parser.
--
pListL ∷ ByteArray π ⇒ Parser π α → Parser π [α]
pListL p = (eof *> pure []) <|> ((:) <$> p <*> pListL p) <?> "pListL"

pTake ∷ ByteArray α ⇒ Int → Parser α α
pTake i = Parser $ \a → if i ≤ length a
    then first Right $ splitAt i a
    else (Left "input to short", a)

pTakeBytes ∷ (Bytes α) ⇒ Int → Parser (ByteArrayImpl α) α
pTakeBytes i = pEither fromBytes (pTake i)

pTakeBytesL ∷ ∀ α . (BytesL α, Nat (ByteLengthL α)) ⇒ Parser (ByteArrayImpl α) α
pTakeBytesL = pEither fromBytesL (pTakeL ∷ Parser (ByteArrayImpl α) (ByteArrayL (ByteArrayImpl α) (ByteLengthL α)))

pTakeL ∷ ∀ α n . (ByteArray α, Nat n) ⇒ Parser α (ByteArrayL α n)
pTakeL = pEither fromBytes $ pTake (toInt (undefined ∷ n))

pTakeExcept ∷ ByteArray π ⇒ Int → Parser π π
pTakeExcept i =  Parser $ \a → if i ≤ length a
    then first Right $ splitAtEnd i a
    else (Left "input to short", a)

pTakeExceptBytes ∷ (Bytes α) ⇒ Int → Parser (ByteArrayImpl α) α
pTakeExceptBytes i = pEither fromBytes (pTakeExcept i)

-- | This parser returns the length of the remaining input.
-- It does not consume any bytes.
--
-- Depending on the implementation of 'BackendByteArray' this
-- may not always terminate.
--
pRemaining ∷ ∀ π . ByteArray π ⇒ Parser π Int
pRemaining = Parser $ \a → (Right $ length a, a)

-- | This parser returns all remaining input.
--
-- Depending on the implementation of 'ByteArray' this
-- may not always terminate.
--
pTakeAll ∷ ByteArray α ⇒ Parser α α
pTakeAll = Parser $ \a → (Right a, empty)

-- | This parser applies 'fromBytes' on all remaining input
--
-- Depending on the implementation of 'ByteArray' this
-- may not always terminate.
--
pTakeAllBytes ∷ (Bytes α) ⇒ Parser (ByteArrayImpl α) α
pTakeAllBytes = pEither fromBytes pTakeAll

pSha512_256 ∷ ByteArray α ⇒ Parser α (ByteArrayL α Sha512_256Length)
pSha512_256 = pTakeBytesL <?> "pSha512_256"

pAesIV ∷ (BytesL AesIV) ⇒ Parser (ByteArrayImpl AesIV) AesIV
pAesIV = pTakeBytesL <?> "pAesIV"

pAes256mac ∷ (BytesL AesIV) ⇒ Parser (ByteArrayImpl AesIV) (AesIV, (ByteArrayImpl AesIV), ByteArrayL (ByteArrayImpl AesIV) Sha512_256Length)
pAes256mac = (,,)
    <$> pAesIV
    <*> pTakeExcept sha512_256Length
    <*> pSha512_256
    <?> "pAes256mac"

(<?>) ∷ ∀ π α . ByteArray π ⇒ Parser π α → String → Parser π α
(<?>) p s = Parser $ \(a ∷ π) → case (unBAP p) a of
    (Left e, _) → (Left ("in " ⊕ s ⊕ ": " ⊕  e), a)
    x → x

infixl 3 <?>

-- | This parser consumes no input. It never fails.
--
isEof ∷ ByteArray π ⇒ Parser π Bool
isEof = Parser $ \case
    a | length a ≡ 0 → (Right True, a)
      | otherwise → (Right False, a)

eof ∷ ByteArray π ⇒ Parser π ()
eof = Parser $ \case
    a| length a ≡ 0 → (Right (), a)
     | otherwise → (Left ("eof: remaining input: " ⊕ to16 a), a)

parse ∷ (Code16 π, ByteArray π) ⇒ Parser π α → π → Either String α
parse = parse' ""

parse' ∷ (Code16 π, ByteArray π) ⇒ String → Parser π α → π → Either String α
parse' s (Parser p) a = case p a of
    (Right r, a') → if length a' ≡ 0
        then Right r
        else Left $ "failed to consume all input while parsing" ⊕ ss ⊕ "; remaining bytes are: " ⊕ to16 a'
    (Left e, a') → Left $ "failed to parse" ⊕ ss ⊕ ": " ⊕ e ⊕ ". remaining bytes are: " ⊕ to16 a'
  where
    ss = if s ≡ "" then "" else " " ⊕ s

instance ByteArray π ⇒ Functor (Parser π) where
    fmap f (Parser p) = Parser $ first (fmap f) ∘ p

instance ByteArray π ⇒ Applicative (Parser π) where
    pure x = Parser $ \a → (Right x, a)
    (Parser p0) <*> (Parser p1) = Parser $ \a →
        case p0 a of
            (Left l, _) → (Left l, a)
            (Right r, a') → first (fmap r) $ (p1 a')

instance ByteArray π ⇒ Alternative (Parser π) where
    (<|>) a b = Parser $ \x → case unBAP a x of
        r@(Right {}, _) → r
        (Left s, _) → case unBAP b x of
            r'@(Right {}, _) → r'
            (Left s', t) → (Left ("[" ⊕ s ⊕ "," ⊕ s' ⊕ "]"), t)
