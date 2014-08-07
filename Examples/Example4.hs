{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import PC.Crypto.Prim.Curve25519
import Data.Byteable as B
import PC.Bytes.ByteArray as BA
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.DJB
import "crypto-random" Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad

type SecurityParameter = Int           -- ^ Jeff: specify bounds?
type Secret            = B.ByteString  -- ^ Jeff: specify bounds?
{-|
  Generate a cryptographically strong secret of length nBits
  Could get used as a symmetric key, hmac key, etc.
  Or could get used to derive a secret (private) key.
  Not currently using this, and need to be more efficient in use of RNG
  Ex: make RNG an optional parameter?
-}
genRandSecret :: SecurityParameter -> IO Secret
genRandSecret nBits = do
  pool <- createEntropyPool
  let rng = cprgCreate pool :: SystemRNG
  let (secret, _) = cprgGenerate nBits rng
  return secret

-- NOTE: in TWC/Crypto/DJB.hs:
-- type DhSecretKey = Curve25519.SecretKey
-- type DhPublicKey = Curve25519.PublicKey
--
--
{-|
 - Generate a Diffie-Hellman Public/Private Key Pair.
 - Write them to separate, specified files. 
-}
genDhKeypairFiles :: FilePath -> FilePath -> IO ()
genDhKeypairFiles encPkFile encSkFile = do
  (encPk, encSk) <- createDhKeypair
  B.writeFile encPkFile $ B.toBytes encPk
  B.writeFile encSkFile $ B.toBytes encSk
  return ()

roundTripTest :: IO()
roundTripTest = do
  (encPk, encSk) <- createDhKeypair
  let bytePk = B.toBytes encPk
      byteSk = B.toBytes encSk
      -- eccPk::DhPublicKey  = (either error id $ fromBytes bytePk)
  return ()

{-
genDhKey :: B.ByteString -> B.ByteString -> B.ByteString
genDhKey sk pk = 
    TWC.Crypto.DJB.dh ecSk ecPk
      where ecSk = (either error id $ fromBytes sk)
            ecPk = (either error id $ fromBytes pk)
-}

encryptStdin :: B.ByteString -> B.ByteString -> IO ()
encryptStdin key nonce = do
    let state = 
         chachaInit256 (either error id $ 
                        fromBytes key) (either error id $ fromBytes nonce)
    L.interact (runEncrypt nonce state)
  where runEncrypt nonce state lbs =
            L.chunk nonce (loop state lbs)
        loop state lbs
            | L.null lbs = L.empty
            | otherwise   =
                let (l1,l2) = L.splitAt 1024 lbs 
                    (encrypted, nstate) = chachaEncrypt state (L.toStrict l1)
                 in L.chunk encrypted (loop nstate l2)

symEncryptStdin keyFile = do
    entropy <- createEntropyPool
    let rng1          = cprgCreate entropy :: SystemRNG
        (key, rng2)   = cprgGenerate 32 rng1
        (nonce, rng3) = cprgGenerate 8 rng2

    B.writeFile keyFile key
    encryptStdin key nonce

pkEncryptStdin skFile pkFile = do
    entropy <- createEntropyPool
    skBytes <- B.readFile skFile
    unless (B.length skBytes == 32) $ error "secret key length not 256 bits"
    pkBytes <- B.readFile pkFile
    unless (B.length pkBytes == 32) $ error "public key length not 256 bits"
    let rng1       = cprgCreate entropy :: SystemRNG
        (nonce, _) = cprgGenerate 8 rng1
    return ()

decryptStdin :: B.ByteString -> IO ()
decryptStdin key = 
    L.interact (runDecrypt key)
  where runDecrypt key lbs =
            let (nonce, lbs') = L.splitAt 8 lbs
                state = 
                  chachaInit256 (either error id $ fromBytes key) 
                                (either error id $ fromBytes $ L.toStrict nonce)
             in loop state lbs'
        loop state lbs
            | L.null lbs = L.empty
            | otherwise  =
                let (l1,l2) = L.splitAt 1024 lbs
                    (decrypted, nstate) = chachaEncrypt state (L.toStrict l1)
                 in L.chunk decrypted (loop nstate l2)

symDecryptStdin keyFile = do
    key <- B.readFile keyFile
    unless (B.length key == 32) $ error "key length must be 256 bits"
    decryptStdin key


-- |To encrypt, {prog} {key} > {cipher}  which will generate key and cipher
-- |To decrypt, {prog} {key} < {cipher} > {cleartext}
main = do
    args <- getArgs
    case args of
        ["keygen",pkFile, skFile] -> genDhKeypairFiles pkFile skFile
        ["encrypt",keyFile] -> symEncryptStdin keyFile
        ["decrypt",keyFile] -> symDecryptStdin keyFile
        ["pkencrypt",skFile, pkFile] -> pkEncryptStdin skFile pkFile
        _         -> error "usage: cipher [encrypt|decrypt] <keyfile>"
