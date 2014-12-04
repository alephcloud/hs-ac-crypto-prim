{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
module Main where

import Data.ByteString.Base16 as B16
import Data.ByteString.Base64 as B64
import PC.Crypto.Prim.Poly1305
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Bytes.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Internal as L
import System.Environment
import Control.Monad
import Control.Applicative

withBase64 :: String -> B.ByteString -> (B.ByteString -> IO a) -> IO a
withBase64 s bs f =
    case B64.decode bs of
        Left err -> error ("decoding Base64 " ++ show s ++ " : " ++ show err) 
        Right v  -> f v

main = do
    args <- getArgs
    
    case args of
        ["init"] -> do
            macKey <- (either error id . fromBytes <$> getRandom 32) :: IO MacKey
            putStrLn $ BC.unpack $ B64.encode $ toBytes $ macKey
        [mackey64,dat64] ->
            withBase64 "mac-key" (BC.pack mackey64) $ \mackeyBs ->
            withBase64 "data" (BC.pack dat64)       $ \dat      -> do
                case fromBytes mackeyBs of
                    Left err     -> error ("invalid poly1305 mac key: " ++ err)
                    Right macKey -> do
                        let result = mac macKey dat
                        putStrLn $ BC.unpack $ B16.encode $ toBytes result
        _            -> error "usage: poly1305 [ init | <mackey-base64> <data-base64> ]"
