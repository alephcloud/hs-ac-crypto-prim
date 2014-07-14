-- all of DJB's suite exported
-- in one single module.
--
{-# LANGUAGE PackageImports #-}
module TWC.Crypto.DJB
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

    -- * Ciphers
    , Salsa
    , salsaInit
    , salsaEncrypt

    , ChaCha
    , chachaInit
    , chachaEncrypt

    -- * MAC
    , Poly1305
    , macInitialize
    , macUpdate
    , macFinalize
    , mac
    ) where

import Data.ByteString (ByteString)
import Data.Byteable
import "crypto-random" Crypto.Random
import qualified Crypto.Cipher.Salsa as Salsa
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Crypto.DH.Curve25519 as Curve25519
import qualified Crypto.Sign.Ed25519 as Ed25519

-- FIXME unify signature and dh secret/public keys.

type SignSecretKey = Ed25519.SecretKey
type SignPublicKey = Ed25519.PublicKey

type DhSecretKey = Curve25519.SecretKey
type DhPublicKey = Curve25519.PublicKey

type ChaCha = ChaCha.State
type Salsa = Salsa.State
type Poly1305Ctx = Poly1305.Ctx
type Poly1305 = Poly1305.Auth


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

chachaInit :: Byteable key => key -> ByteString -> ChaCha
chachaInit = ChaCha.initialize 20

salsaInit :: Byteable key => key -> ByteString -> Salsa
salsaInit = Salsa.initialize 20

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

mac :: Byteable key => key -> ByteString -> Poly1305
mac = Poly1305.auth
