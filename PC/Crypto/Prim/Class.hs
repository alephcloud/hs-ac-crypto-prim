-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

-- |
-- Module      : PC.Crypto.Prim.Class
-- Copyright: Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
-- License: All Rights Reserved, see LICENSE file of the package
-- Maintainer  : support@pivotmail.com
--
-- Framework for cryptographic operations

{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module PC.Crypto.Prim.Class
    (
    -- * Types
      DhSecret(..)
    , KeyPair(..)
    , keypairGenerate
    -- * Classes
    , AsymmetricCrypto(..)
    , DiffieHellmanAlgorithm(..)
    , SignatureAlgorithm(..)
    ) where

import Control.Applicative
import Control.DeepSeq

import PC.Bytes.ByteArray
import PC.Crypto.Prim.SafeEq
import PC.Crypto.Prim.Imports

-- | A Diffie Hellman secret
newtype DhSecret = DhSecret BackendByteArray
    deriving (Show,Bytes,NFData,SafeEq)
instance Eq DhSecret where
    (==) = safeEq

-- | A KeyPair containing a public key and a secret key
-- for a given algorithm
data KeyPair sec pub = KeyPair !sec !pub
    deriving (Show,Eq)

-- | generate a asymmetric key pair (public key and secret key) from system entropy
keypairGenerate :: AsymmetricCrypto secretKey publicKey => IO (KeyPair secretKey publicKey)
keypairGenerate = (\sec -> KeyPair sec (asymmetricGetPublic sec)) <$> asymmetricKeyGenerate

-- | Define a class of secret key and public key that are use
-- for asymmetric cryptography (also known as public-key cryptography)
class ( Bytes secretKey
      , Bytes publicKey
      , ToACN secretKey, FromACN secretKey
      , ToACN publicKey, FromACN publicKey
      , Eq secretKey
      , Eq publicKey)
    => AsymmetricCrypto secretKey publicKey | secretKey -> publicKey
                                            , publicKey -> secretKey where

    -- | Generate a secret key from system entropy
    asymmetricKeyGenerate  :: IO secretKey

    -- | Generate the public key from the secret key
    asymmetricGetPublic :: secretKey -> publicKey

-- | The following is defined for asymmetric crypto algorithm that can create a shared secret
-- from a public key and a secret key, using the Diffie Hellman algorithm.
--
-- The following property should hold given two key pairs (sec1, pub1) and (sec2, pub2)
--
-- > dhSecret sec1 pub2 == dhSecret sec2 pub1
--
class AsymmetricCrypto secretKey publicKey
    => DiffieHellmanAlgorithm secretKey publicKey | secretKey -> publicKey
                                                  , publicKey -> secretKey where

    -- | Generate a Diffie Hellman secret key
    dhSecret :: secretKey -> publicKey -> DhSecret

    -- | Make a Diffie Hellman secret key from a unique public key. This should only use
    -- when the "public" key has been combined, otherwise your resulting DhSecret
    -- is not secret.
    --
    -- /Warning:/ This is an escape hatch, most of the time you should only use 'dhSecret'
    dhFromPublicKey :: publicKey -> DhSecret

-- | Basic class to generate digital signature through asymmetric cryptography
--
-- The only property is that given a key pair (sec,pub) for any message m:
-- > verify pub m . sign sec m == True
class ( Bytes signature
      , AsymmetricCrypto secretKey publicKey)
    => SignatureAlgorithm signature secretKey publicKey | signature -> secretKey
                                                        , signature -> publicKey
                                                        , publicKey -> signature where

    -- | Generate a signature from a value that can be serialized to bytes
    sign   :: Bytes a => secretKey -> a -> IO signature

    -- | Verify a signature for a value that can be serialized to bytes
    verify :: Bytes a => publicKey -> a -> signature -> Bool
