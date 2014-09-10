-- ChaCha
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.ChaCha
    (
    -- * ChaCha types
      ChaCha
    , ChaChaKey256Length
    , ChaChaKey128Length
    , ChaChaNonceLength
    , ChaChaKey256
    , ChaChaKey128
    , ChaChaNonce

    -- * Methods
    , chachaInit256
    , chachaInit128
    , chachaEncrypt
    ) where

import Data.ByteString (ByteString)
import Data.Byteable (Byteable)
import "crypto-random" Crypto.Random
import qualified Crypto.Cipher.ChaCha as ChaCha

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

type ChaCha = ChaCha.State

type ChaChaKey128Length = 16
type ChaChaKey256Length = 32
type ChaChaNonceLength = 8

newtype ChaChaKey256 = ChaChaKey256 (ByteArrayL ByteString ChaChaKey256Length)
    deriving (Eq,Ord,Code64,Code16)

newtype ChaChaKey128 = ChaChaKey128 (ByteArrayL ByteString ChaChaKey128Length)
    deriving (Eq,Ord,Code64,Code16)

newtype ChaChaNonce = ChaChaNonce (ByteArrayL ByteString ChaChaNonceLength)
    deriving (Eq,Ord,Code64,Code16)

instance Bytes ChaChaKey256 where
    type ByteArrayImpl ChaChaKey256 = ByteString
    toBytes (ChaChaKey256 bytes) = toBytes bytes
    fromBytes = fmap ChaChaKey256 . fromBytes

instance BytesL ChaChaKey256 where
    type ByteLengthL ChaChaKey256 = ChaChaKey256Length
    toBytesL (ChaChaKey256 bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaKey256 . fromBytesL

instance Bytes ChaChaKey128 where
    type ByteArrayImpl ChaChaKey128 = ByteString
    toBytes (ChaChaKey128 bytes) = toBytes bytes
    fromBytes = fmap ChaChaKey128 . fromBytes

instance BytesL ChaChaKey128 where
    type ByteLengthL ChaChaKey128 = ChaChaKey128Length
    toBytesL (ChaChaKey128 bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaKey128 . fromBytesL

instance Bytes ChaChaNonce where
    type ByteArrayImpl ChaChaNonce = ByteString
    toBytes (ChaChaNonce bytes) = toBytes bytes
    fromBytes = fmap ChaChaNonce . fromBytes

instance BytesL ChaChaNonce where
    type ByteLengthL ChaChaNonce = ChaChaNonceLength
    toBytesL (ChaChaNonce bytes) = toBytesL bytes
    fromBytesL = fmap ChaChaNonce . fromBytesL

chachaInit256 :: ChaChaKey256 -> ChaChaNonce -> ChaCha
chachaInit256 key nonce = ChaCha.initialize 20 (toBytes key) (toBytes nonce)

chachaInit128 :: ChaChaKey128 -> ChaChaNonce -> ChaCha
chachaInit128 key nonce = ChaCha.initialize 20 (toBytes key) (toBytes nonce)

chachaEncrypt :: ChaCha -> ByteString -> (ByteString, ChaCha)
chachaEncrypt = ChaCha.combine
