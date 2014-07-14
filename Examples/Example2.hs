{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
module Main where

import TWC.Crypto.DJB
import "crypto-random" Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad

main = do
    -- generate secret key / public key from System RNG
    entropy <- createEntropyPool

    let rng            = cprgCreate entropy :: SystemRNG
        (secretKey, _) = createDhSecretKey rng
        publicKey      = createDhPublicKey secretKey

    return ()
