{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Data.ByteString.Base64 as BS
import Crypto.DH.Curve25519 as C2
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

type SecurityParameter = Int  
type Secret            = B.ByteString 

-- Note: not currently used
genRandSecret :: SecurityParameter -> IO Secret
genRandSecret nBits = do
  pool <- createEntropyPool
  let rng = cprgCreate pool :: SystemRNG
  let (secret, _) = cprgGenerate nBits rng
  return secret

-- Note: only used by genDhKeypairFiles
genDhKeyPairBase64Bytes :: IO (B.ByteString, B.ByteString)
genDhKeyPairBase64Bytes = do
  (encPk, encSk) <- createDhKeypair
  let encPkBase64 = BS.encode $ B.toBytes encPk
      encSkBase64 = BS.encode $ B.toBytes encSk
  return (B.toBytes encPkBase64, B.toBytes encSkBase64)

-- Note: only used by genDhKeypairFiles
writeDhKeypairFiles :: B.ByteString -> B.ByteString -> FilePath -> FilePath -> IO ()
writeDhKeypairFiles encPkBytes encSkBytes encPkFile encSkFile = do
  B.writeFile encPkFile encPkBytes
  B.writeFile encSkFile encSkBytes
  return ()

genDhKeypairFiles :: FilePath -> FilePath -> IO ()
genDhKeypairFiles encSkFile encPkFile = do
  (encPkBase64Bytes, encSkBase64Bytes) <- genDhKeyPairBase64Bytes
  writeDhKeypairFiles encPkBase64Bytes encSkBase64Bytes encPkFile encSkFile
  return ()

testDhRoundTrip :: FilePath -> FilePath -> IO ()
testDhRoundTrip encSkFile encPkFile = do
  genDhKeypairFiles encSkFile encPkFile
  sk <- readDhSk encSkFile
  pk <- readDhPk encPkFile
  return ()

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

pkEncryptStdin :: FilePath -> FilePath -> IO ()
pkEncryptStdin skFile pkFile = do
  sourceSk <- readDhSk skFile
  destPk   <- readDhPk pkFile
  entropy <- createEntropyPool
  let rng1       = cprgCreate entropy :: SystemRNG
      (nonce, _) = cprgGenerate 8 rng1
      symkey     = dh sourceSk destPk
  encryptStdin symkey nonce
  return ()

pkDecryptStdin :: FilePath -> FilePath -> IO ()
pkDecryptStdin skFile pkFile = do
  destSk   <- readDhSk skFile
  sourcePk <- readDhPk pkFile
  let symkey = dh destSk sourcePk
  decryptStdin symkey
  return ()

readDhPk :: FilePath -> IO C2.PublicKey
readDhPk pkFile = do
  encPkBase64 <- B.readFile pkFile
  let pk = C2.PublicKey $ BS.decodeLenient encPkBase64
  return (pk)

readDhSk :: FilePath -> IO C2.SecretKey
readDhSk skFile = do
  encSkBase64 <- B.readFile skFile
  let sk = C2.SecretKey $ BS.decodeLenient encSkBase64
  return (sk)

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
        ["test", skFile, pkFile] -> testDhRoundTrip skFile pkFile
        ["keygen",skFile, pkFile] -> genDhKeypairFiles skFile pkFile
        ["encrypt",keyFile] -> symEncryptStdin keyFile
        ["decrypt",keyFile] -> symDecryptStdin keyFile
        ["pkencrypt",skFile, pkFile] -> pkEncryptStdin skFile pkFile
        ["pkdecrypt",skFile, pkFile] -> pkDecryptStdin skFile pkFile
        _         -> error "usage: cipher [encrypt|decrypt] <keyfile>"


