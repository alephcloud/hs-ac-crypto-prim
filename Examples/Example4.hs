{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
module Main where

import Data.ByteString.Base64 as BS
import PC.Crypto.Prim.Curve25519 as C2
import PC.Crypto.Prim.ChaCha
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad
import Control.Applicative

type SecurityParameter = 32

newtype Secret = Secret (ByteArrayL SecurityParameter)

-- Note: not currently used
genRandSecret :: IO Secret
genRandSecret = Secret <$> randomBytesL

-- Note: only used by genDhKeypairFiles
genDhKeyPairBase64Bytes :: IO (B.ByteString, B.ByteString)
genDhKeyPairBase64Bytes = do
  encSk <- C2.createSecretKey
  let encPk = C2.createPublicKey encSk
  let encPkBase64 = BS.encode $ toBytes encPk
      encSkBase64 = BS.encode $ toBytes encSk
  return ({-toBytes-} encPkBase64, toBytes encSkBase64)

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

encryptStdin :: ChaChaKey256 -> ChaChaNonce -> IO ()
encryptStdin key nonce = do
    let state = chachaInit256 key nonce
    L.interact (runEncrypt nonce state)
  where runEncrypt nonce state lbs =
            L.chunk (toBytes nonce) (loop state lbs)
        loop state lbs
            | L.null lbs = L.empty
            | otherwise   =
                let (l1,l2) = L.splitAt 1024 lbs 
                    (encrypted, nstate) = chachaEncrypt state (L.toStrict l1)
                 in L.chunk encrypted (loop nstate l2)

symEncryptStdin keyFile = do
    key   <- either error id . fromBytesL <$> randomBytesL
    nonce <- either error id . fromBytesL <$> randomBytesL

    B.writeFile keyFile (toBytes key)
    encryptStdin key nonce

pkEncryptStdin :: FilePath -> FilePath -> IO ()
pkEncryptStdin skFile pkFile = do
  sourceSk <- readDhSk skFile
  destPk   <- readDhPk pkFile
  nonce <- either error id . fromBytesL <$> randomBytesL
  let symkey = either error id . fromBytes . B.take 32 . toBytes $ C2.dh sourceSk destPk
  encryptStdin symkey nonce
  return ()

pkDecryptStdin :: FilePath -> FilePath -> IO ()
pkDecryptStdin skFile pkFile = do
  destSk   <- readDhSk skFile
  sourcePk <- readDhPk pkFile
  let symkey = either error id . fromBytes . B.take 32 . toBytes $ C2.dh destSk sourcePk
  decryptStdin symkey
  return ()

readDhPk :: FilePath -> IO C2.PublicKey
readDhPk pkFile = do
  encPkBase64 <- B.readFile pkFile
  let pk = either error id $ fromBytes $ BS.decodeLenient encPkBase64
  return pk

readDhSk :: FilePath -> IO C2.SecretKey
readDhSk skFile = do
  encSkBase64 <- B.readFile skFile
  let sk = either error id $ fromBytes $ BS.decodeLenient encSkBase64
  return sk

decryptStdin :: ChaChaKey256 -> IO ()
decryptStdin key = 
    L.interact (runDecrypt key)
  where runDecrypt key lbs =
            let (nonce, lbs') = L.splitAt 8 lbs
                state = chachaInit256 key (either error id $ fromBytes $ L.toStrict nonce)
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
    decryptStdin (either error id $ fromBytes key)


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


