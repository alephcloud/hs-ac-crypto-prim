-- all of DJB's suite exported
-- in one single module.
--
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.DJB
    (
    -- * Signature
      SignSecretKey
    , SignPublicKey
    , createSignatureKeypair
    , sign
    , verify

    -- * Diffie Hellman
    , DhSecretKey
    , DhPublicKey
    , createDhKeypair
    , createDhPublicKey
    , createDhSecretKey
    , dh

    -- * Salsa symmetric cipher
    , Salsa
    , SalsaKey256Length
    , SalsaKey128Length
    , SalsaNonceLength
    , SalsaKey256
    , SalsaKey128
    , SalsaNonce
    , salsaInit256
    , salsaInit128

    -- * ChaCha symmetric cipher
    , ChaCha
    , ChaChaKey256Length
    , ChaChaKey128Length
    , ChaChaNonceLength
    , ChaChaKey256
    , ChaChaKey128
    , ChaChaNonce
    , chachaInit256
    , chachaInit128
    , chachaEncrypt

    -- * MAC
    , MacKey
    , MacKeyLength
    , Poly1305
    , macInitialize
    , macUpdate
    , macFinalize
    , mac
    ) where

import Data.ByteString (ByteString)
import Data.Byteable (Byteable)
import "crypto-random" Crypto.Random
import qualified Crypto.Cipher.Salsa as Salsa
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Crypto.DH.Curve25519 as Curve25519
import qualified Crypto.Sign.Ed25519 as Ed25519

import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

-- FIXME unify signature and dh secret/public keys.

type SignSecretKey = Ed25519.SecretKey
type SignPublicKey = Ed25519.PublicKey

type DhSecretKey = Curve25519.SecretKey
type DhPublicKey = Curve25519.PublicKey

type ChaCha = ChaCha.State
type Salsa = Salsa.State
type Poly1305Ctx = Poly1305.Ctx
type Poly1305 = Poly1305.Auth

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

type SalsaKey128Length = 16
type SalsaKey256Length = 32
type SalsaNonceLength = 8

newtype SalsaKey256 = SalsaKey256 (ByteArrayL ByteString SalsaKey256Length)
    deriving (Eq,Ord,Code64,Code16)

newtype SalsaKey128 = SalsaKey128 (ByteArrayL ByteString SalsaKey128Length)
    deriving (Eq,Ord,Code64,Code16)

newtype SalsaNonce = SalsaNonce (ByteArrayL ByteString SalsaNonceLength)
    deriving (Eq,Ord,Code64,Code16)

instance Bytes SalsaKey256 where
    type ByteArrayImpl SalsaKey256 = ByteString
    toBytes (SalsaKey256 bytes) = toBytes bytes
    fromBytes = fmap SalsaKey256 . fromBytes

instance BytesL SalsaKey256 where
    type ByteLengthL SalsaKey256 = SalsaKey256Length
    toBytesL (SalsaKey256 bytes) = toBytesL bytes
    fromBytesL = fmap SalsaKey256 . fromBytesL

instance Bytes SalsaKey128 where
    type ByteArrayImpl SalsaKey128 = ByteString
    toBytes (SalsaKey128 bytes) = toBytes bytes
    fromBytes = fmap SalsaKey128 . fromBytes

instance BytesL SalsaKey128 where
    type ByteLengthL SalsaKey128 = SalsaKey128Length
    toBytesL (SalsaKey128 bytes) = toBytesL bytes
    fromBytesL = fmap SalsaKey128 . fromBytesL

instance Bytes SalsaNonce where
    type ByteArrayImpl SalsaNonce = ByteString
    toBytes (SalsaNonce bytes) = toBytes bytes
    fromBytes = fmap SalsaNonce . fromBytes

instance BytesL SalsaNonce where
    type ByteLengthL SalsaNonce = SalsaNonceLength
    toBytesL (SalsaNonce bytes) = toBytesL bytes
    fromBytesL = fmap SalsaNonce . fromBytesL

createSignatureKeypair :: IO (SignPublicKey, SignSecretKey)
createSignatureKeypair = Ed25519.createKeypair

createDhKeypair :: IO (DhPublicKey, DhSecretKey)
createDhKeypair = Curve25519.createKeypair

createDhPublicKey :: DhSecretKey -> DhPublicKey
createDhPublicKey = Curve25519.createPublicKey

createDhSecretKey :: CPRG rng => rng -> (DhSecretKey, rng)
createDhSecretKey = Curve25519.createSecretKey

sign :: SignSecretKey -> ByteString -> ByteString
sign = Ed25519.sign

verify :: SignPublicKey -> ByteString -> Bool
verify = Ed25519.verify

dh :: DhSecretKey -> DhPublicKey -> ByteString
dh = Curve25519.curve25519

chachaInit256 :: ChaChaKey256 -> ByteString -> ChaCha
chachaInit256 key = ChaCha.initialize 20 (toBytes key)

chachaInit128 :: ChaChaKey128 -> ByteString -> ChaCha
chachaInit128 key = ChaCha.initialize 20 (toBytes key)

salsaInit256 :: SalsaKey256 -> ByteString -> Salsa
salsaInit256 key = Salsa.initialize 20 (toBytes key)

salsaInit128 :: SalsaKey128 -> ByteString -> Salsa
salsaInit128 key = Salsa.initialize 20 (toBytes key)

chachaEncrypt :: ChaCha -> ByteString -> (ByteString, ChaCha)
chachaEncrypt = ChaCha.combine

salsaEncrypt :: Salsa -> ByteString -> (ByteString, Salsa)
salsaEncrypt = Salsa.combine

macInitialize :: Byteable key => key -> Poly1305Ctx
macInitialize = Poly1305.initialize

macUpdate :: Poly1305Ctx -> ByteString -> Poly1305Ctx
macUpdate = Poly1305.update

macFinalize :: Poly1305Ctx -> Poly1305
macFinalize = Poly1305.finalize

type MacKeyLength = 32

newtype MacKey = MacKey (ByteArrayL ByteString MacKeyLength)
    deriving (Eq,Ord,Code64,Code16)

instance Bytes MacKey where
    type ByteArrayImpl MacKey = ByteString
    toBytes (MacKey bytes) = toBytes bytes
    fromBytes = fmap MacKey . fromBytes

instance BytesL MacKey where
    type ByteLengthL MacKey = MacKeyLength
    toBytesL (MacKey bytes) = toBytesL bytes
    fromBytesL = fmap MacKey . fromBytesL

mac :: MacKey -> ByteString -> Poly1305
mac key = Poly1305.auth (toBytes key)
