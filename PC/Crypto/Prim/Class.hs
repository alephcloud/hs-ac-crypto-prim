-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Class
--
-- Please feel free to contact us at licensing@pivotmail.com with any
-- contributions, additions, or other feedback; we would love to hear from
-- you.
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may
-- not use this file except in compliance with the License. You may obtain a
-- copy of the License at http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations
-- under the License.
--
-- |
-- Module      : PC.Crypto.Prim.Class
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
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
