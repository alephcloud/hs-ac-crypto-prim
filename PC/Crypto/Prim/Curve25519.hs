{-# LANGUAGE TypeFamilies #-}
module PC.Crypto.Prim.Curve25519
    ( SecretKey
    , PublicKey
    , dh
    , createSecretKey
    , createPublicKey
    ) where

import PC.Bytes.Codec
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

import qualified Crypto.DH.Curve25519 as Curve25519

import qualified Data.ByteString as B

newtype SecretKey = SecretKey Curve25519.SecretKey
newtype PublicKey = PublicKey Curve25519.PublicKey

instance Bytes SecretKey where
    type ByteArrayImpl SecretKey = BackendByteArray
    toBytes (SecretKey (Curve25519.SecretKey bs)) = bs
    fromBytes b = if B.length b == 32
                    then Right $ SecretKey $ Curve25519.SecretKey b
                    else Left "curve25519: secret key: not valid length. expecting 32 bytes"

instance Bytes PublicKey where
    type ByteArrayImpl PublicKey = BackendByteArray
    toBytes (PublicKey (Curve25519.PublicKey bs)) = bs
    fromBytes b = if B.length b == 32
                    then Right $ PublicKey $ Curve25519.PublicKey b
                    else Left "curve25519: public key: not valid length. expecting 32 bytes"

dh (SecretKey k) (PublicKey p) = PublicKey $ Curve25519.PublicKey $ Curve25519.curve25519 k p

createSecretKey = (SecretKey . snd) `fmap` Curve25519.createKeypair
createPublicKey (SecretKey k) = PublicKey $ Curve25519.createPublicKey k
