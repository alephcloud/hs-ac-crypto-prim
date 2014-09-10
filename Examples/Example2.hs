{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
module Main where

import PC.Crypto.Prim.Curve25519
import PC.Bytes.ByteArrayL
import PC.Bytes.ByteArray
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Applicative
import Control.Monad

main = do
    -- generate secret key / public key from System RNG
    secretKey <- either error id . fromBytesL <$> randomBytesL
    let publicKey = createPublicKey secretKey

    putStrLn $ show $ toBytes publicKey

    return ()
