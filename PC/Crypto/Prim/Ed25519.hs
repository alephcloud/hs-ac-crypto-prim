module PC.Crypto.Prim.Ed25519
    ( Ed25519.SecretKey
    , Ed25519.PublicKey
    -- * key generation
    , createKeypair
    , createSecret
    , createPublic
    -- * basic methods
    , sign
    , verify
    ) where

import Data.ByteString (ByteString)
import Data.Byteable (Byteable)
import qualified Crypto.Sign.Ed25519 as Ed25519

createKeypair :: IO (Ed25519.PublicKey, Ed25519.SecretKey)
createKeypair = Ed25519.createKeypair

createSecret :: IO Ed25519.SecretKey
createSecret = snd `fmap` createKeypair

createPublic :: Ed25519.SecretKey -> Ed25519.PublicKey
createPublic = Ed25519.toPublicKey

sign :: Ed25519.SecretKey -> ByteString -> ByteString
sign = Ed25519.sign

verify :: Ed25519.PublicKey -> ByteString -> Bool
verify = Ed25519.verify
