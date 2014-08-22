{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
module PC.Crypto.Prim.Curve25519
    ( SecretKey
    , PublicKey
    , SecretKeyLength
    , PublicKeyLength
    , dh
    , createSecretKey
    , createPublicKey
    ) where

import PC.Bytes.Codec
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Bytes.Utils

import qualified Crypto.DH.Curve25519 as Curve25519

import qualified Data.ByteString as B

newtype SecretKey = SecretKey Curve25519.SecretKey
newtype PublicKey = PublicKey Curve25519.PublicKey

type SecretKeyLength = 32

secretKeyLength = 32

type PublicKeyLength = 32

publicKeyLength = 32

instance Bytes SecretKey where
    type ByteArrayImpl SecretKey = BackendByteArray
    toBytes (SecretKey (Curve25519.SecretKey bs)) = bs
    fromBytes b = if B.length b == secretKeyLength
                    then Right $ SecretKey $ Curve25519.SecretKey b
                    else Left "curve25519: secret key: not valid length. expecting 32 bytes"

instance BytesL SecretKey where
    type ByteLengthL SecretKey = SecretKeyLength
    toBytesL (SecretKey (Curve25519.SecretKey bs)) = unsafeFromBytes $ padLeft 0 secretKeyLength $ toBytes bs
    fromBytesL = fromBytes . toBytes

instance Bytes PublicKey where
    type ByteArrayImpl PublicKey = BackendByteArray
    toBytes (PublicKey (Curve25519.PublicKey bs)) = bs
    fromBytes b = if B.length b == publicKeyLength
                    then Right $ PublicKey $ Curve25519.PublicKey b
                    else Left "curve25519: public key: not valid length. expecting 32 bytes"

instance BytesL PublicKey where
    type ByteLengthL PublicKey = PublicKeyLength
    toBytesL (PublicKey (Curve25519.PublicKey bs)) = unsafeFromBytes $ padLeft 0 publicKeyLength $ toBytes bs
    fromBytesL = fromBytes . toBytes

dh (SecretKey k) (PublicKey p) = PublicKey $ Curve25519.PublicKey $ Curve25519.curve25519 k p

createSecretKey = (SecretKey . snd) `fmap` Curve25519.createKeypair
createPublicKey (SecretKey k) = PublicKey $ Curve25519.createPublicKey k