-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.MAC.Poly1305 (Auth (..))
import TWC.Crypto.DJB

import Data.ByteString (ByteString)
import qualified Crypto.DH.Curve25519 as Curve25519
import Crypto.Cipher.ChaCha (State)
import Crypto.Random.API

type PublicKey = Curve25519.PublicKey
type SecretKey = Curve25519.SecretKey

genChaChaKey :: SecretKey -> PublicKey -> ByteString
genChaChaKey sk pk = dh sk pk

genChaChaState :: ByteString -> State
genChaChaState symkey = chachaInit symkey nonce
                          where nonce = "12345678"

--genNonce :: IO ByteString
--genNonce = getSystemEntropy 8
-- QUESTION FOR JEFF: Clean way to generate a 64-bit
-- or 96-bit nonce?

{-
genIV :: IO -> IV
genIV = <something>

streamEncrypt :: Key -> String -> String
streamEncrypt str = do
  let iv = genIV
  let initChaCha = chachaInit Key iv
  (IV (chachaEncrypt initChaCha str))

streamDecrypt :: IV -> Key -> String -> String
streamDecrypt iv key str = do
  let initChaCha = chachaInit key iv
  chachaEncrypt initChaCha str

poly1305Mac :: Key -> String -> Integer
poly1305Mac key string = 
  let Auth macmac = mac key string
  return macmac
-}
-- end new

type Message = ByteString
type CipherText = (ByteString, ChaCha)

pkstreamenc :: SecretKey -> PublicKey -> Message -> CipherText
pkstreamenc sk pk msg = 
    chachaEncrypt chacha_state msg
        where chacha_state = genChaChaState shared_secret
                where shared_secret = genChaChaKey sk pk

main :: IO ()
main = do
  (pksig, sksig) <- createSignatureKeypair
  print $ verify pksig (sign sksig "hi")
  (_, skdh_A) <- createDhKeypair  -- key pair for Alice
  (pkdh_B, _) <- createDhKeypair  -- key pair for Bob

  let shared_secret = genChaChaKey skdh_A pkdh_B
  let chacha_state = genChaChaState shared_secret 
  let (cipher_text, new_state) = 
          chachaEncrypt chacha_state "hello" 

--  let (cipher_text, new_state) = pkstreamenc skdh_A pkdh_B "hello"
--
  let (plain_text, nnew) = 
          chachaEncrypt chacha_state cipher_text
  print $ plain_text
  let Auth macmac = mac shared_secret "hello"
  print macmac

