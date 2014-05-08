{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE CPP #-}

module TWC.Crypto.ByteArray
( ByteArray(..)
, Bytes(..)
, BackendByteArray
, module TWC.Crypto.Codec
) where

import Control.Monad.IO.Class

import Data.Monoid
import Data.Word

import Prelude hiding (splitAt, length, take, drop)
import Prelude.Unicode

import TWC.Crypto.Codec

import Control.Applicative hiding (empty)
import Control.Monad.IO.Class

import Crypto.Random

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64.URL as B64
import Data.Monoid.Unicode
import qualified Data.List as L
import Data.Word

import Prelude hiding (take, drop, length, splitAt)
import Prelude.Unicode

import TWC.Crypto.Codec

import Data.ByteString (ByteString)

-- | The class of ByteArrays for usage with
-- cryptographic ciphers.
--
-- Mininmal complete definition:
-- 'length', 'splitAt', 'toList', 'fromList', 'randomBytes'
--
class (Eq α, Ord α, Monoid α, Code64 α, Code16 α) ⇒ ByteArray α where

    length ∷ α → Int
    splitAt ∷ Int → α → (α, α)
    randomBytes ∷ MonadIO μ ⇒ Int → μ α
    toList ∷ α → [Word8]
    fromList ∷ [Word8] → α

    splitAtEnd ∷ Int → α → (α, α)
    take ∷ Int → α → α
    takeEnd ∷ Int → α → α
    drop ∷ Int → α → α
    dropEnd ∷ Int → α → α
    empty ∷ α

    -- Default implementations
    splitAtEnd i a = splitAt (length a - i) a
    take i = fst ∘ splitAt i
    takeEnd i = snd ∘ splitAtEnd i
    drop i = snd ∘ splitAt i
    dropEnd i = fst ∘ splitAtEnd i
    empty = mempty

    {-# INLINABLE splitAtEnd #-}
    {-# INLINABLE take #-}
    {-# INLINEABLE takeEnd #-}
    {-# INLINEABLE drop #-}
    {-# INLINEABLE dropEnd #-}

-- | The class of types that can be serialized to ByteArrays.
--
-- Note that 'ByteArray' implementation is fixed. In order
-- to create different implementation of 'ByteArray'
-- a newtype wrapper can be used.
--
-- Minimal complete defintion:
-- 'toBytes', 'fromBytes'
--
class (ByteArray (ByteArrayImpl α)) ⇒ Bytes α where
    type ByteArrayImpl α
    toBytes ∷ α → (ByteArrayImpl α)
    fromBytes ∷ (ByteArrayImpl α) → Either String α

{- This won't work because the type familie instance
 - would conflict with any other instance. But
 - given that there will be only a limited number
 - of implementations it is fine to define these
 - instances explicitely.
 -
instance (ByteArray α) ⇒ Bytes α where
    type ByteArrayImpl α = α
    toBytes = id
    fromBytes = Right

    {-# INLINABLE toBytes #-}
    {-# INLINABLE fromBytes #-}
-}

{-
-- -------------------------------------------------------------------------- --
-- * Serialization

instance (Code64 α, Bytes α) ⇒ Code64 α where
    to64 = to64 ∘ toBytes
    from64 = fromBytes <=< from64

instance (Code16 α, Bytes α) ⇒ Code16 α where
    to16 = to16 ∘ toBytes
    from16 = fromBytes <=< from16
-}

#ifdef __HASTE__

type BackendByteArray = SjclByteArray

#error "haste bytearray backend not defined anymore"

#else

type BackendByteArray = ByteString

instance ByteArray B.ByteString where

    length = B.length
    take = B.take
    drop = B.drop
    splitAt = B.splitAt
    fromList = B.pack
    toList = B.unpack

    {-# INLINABLE length #-}
    {-# INLINABLE take #-}
    {-# INLINABLE drop #-}
    {-# INLINABLE splitAt #-}
    {-# INLINABLE fromList #-}
    {-# INLINABLE toList #-}

    randomBytes i = liftIO $ do
        rng ← cprgCreate <$> createEntropyPool :: IO SystemRNG
        return $ fst ∘ cprgGenerate i $ rng

instance Bytes B.ByteString where
    type ByteArrayImpl B.ByteString = B.ByteString
    toBytes = id
    fromBytes = Right

    {-# INLINABLE toBytes #-}
    {-# INLINABLE fromBytes #-}

-- | Move this instance to a separate package?
--
-- The advanage of this instance is that it works for every platform.
--
instance ByteArray [Word8] where

    length = L.length
    take = L.take
    drop = L.drop
    splitAt = L.splitAt
    fromList = id
    toList = id

    {-# INLINABLE length #-}
    {-# INLINABLE take #-}
    {-# INLINABLE drop #-}
    {-# INLINABLE splitAt #-}
    {-# INLINABLE fromList #-}
    {-# INLINABLE toList #-}

    randomBytes i = liftIO $ do
        rng ← cprgCreate <$> createEntropyPool :: IO SystemRNG
        return $ B.unpack ∘ fst ∘ cprgGenerate i $ rng

instance Bytes [Word8] where
    type ByteArrayImpl [Word8] = [Word8]
    toBytes = id
    fromBytes = Right

    {-# INLINABLE toBytes #-}
    {-# INLINABLE fromBytes #-}

-- -------------------------------------------------------------------------- --
-- * Codec Instances

-- -------------------------------------------------------------------------- --
-- ** Base64 serialization

instance Code64 B.ByteString where
    to64 = B8.unpack ∘ urlEncode64
    from64 = urlDecode64 ∘ B8.pack

instance Code64 [Word8] where
    to64 = B8.unpack ∘ urlEncode64 ∘ B.pack
    from64 = fmap B.unpack ∘ urlDecode64 ∘ B8.pack

-- -------------------------------------------------------------------------- --
-- ** Hex serialization

instance Code16 B.ByteString where
    to16 = B8.unpack ∘ B16.encode
    from16 = Right ∘ fst ∘ B16.decode ∘ B8.pack

instance Code16 [Word8] where
    to16 = B8.unpack ∘ B16.encode ∘ B.pack
    from16 = Right ∘ B.unpack ∘ fst ∘ B16.decode ∘ B8.pack

-- -------------------------------------------------------------------------- --
-- ** Utils

urlEncode64 ∷ B.ByteString → B.ByteString
urlEncode64 = fst . B8.spanEnd (≡ '=') . B64.encode

urlDecode64 ∷ B.ByteString → Either String B.ByteString
urlDecode64 s = let l = B.length s
                    x = l `mod` 4
                in  B64.decode $ s ⊕ B8.replicate (4 - if x ≡ 0 then 4 else x) '='

instance Bytes String where
    type ByteArrayImpl String = BackendByteArray
    toBytes = B8.pack
    fromBytes = Right ∘ B8.unpack

#endif
