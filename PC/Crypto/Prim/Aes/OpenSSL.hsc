-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE DeriveDataTypeable #-}
module PC.Crypto.Prim.Aes.OpenSSL
    ( isSupportedGCM
    , encryptGCM
    , decryptGCM
    , OpenSSLGcmError(..)
    ) where

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER > 0x10001000
#define OPENSSL_HAS_PBKDF2
#define OPENSSL_HAS_GCM
#endif

import Control.Monad (when)
import Control.Exception (Exception, throwIO)
import Data.Typeable
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils (copyBytes)
import Foreign.C.Types
import Foreign.Storable
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.Byteable as B
import System.IO.Unsafe

type GCMCtx = ForeignPtr EVP_CIPHER_CTX

data Direction = DirectionEncrypt | DirectionDecrypt

newtype OpenSSLGcmError = OpenSSLGcmError String
    deriving (Show,Read,Eq,Typeable)

instance Exception OpenSSLGcmError

isSupportedGCM :: Bool
isSupportedGCM = unsafePerformIO $ do
    cipher <- openssl_c_aes_256_gcm
    return (cipher /= nullPtr)
{-# NOINLINE isSupportedGCM #-}

withGCM :: Direction -> ByteString -> ByteString -> (Ptr EVP_CIPHER_CTX -> IO a) -> a
withGCM direction key iv f = unsafePerformIO $ do
    cipher <- openssl_c_aes_256_gcm
    when (cipher == nullPtr) $ error "openssl doesn't have a GCM cipher"
    fptr <- contextNew $ \ctx -> checkRet "encryptinit_ex" (openssl_c_encryptinit_ex ctx cipher nullEngine nullPtr nullPtr)
    withForeignPtr fptr $ \ctx    ->
        B.withBytePtr key $ \keyPtr ->
        B.withBytePtr iv  $ \ivPtr  -> do
            checkRet "ctx_ctrl_set_ivlen" (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_SET_IVLEN 12 nullPtr)
            case direction of
                DirectionEncrypt -> checkRet "encryptinit_ex" (openssl_c_encryptinit_ex ctx nullPtr nullEngine keyPtr ivPtr)
                DirectionDecrypt -> checkRet "decryptinit_ex" (openssl_c_decryptinit_ex ctx nullPtr nullEngine keyPtr ivPtr)
            f ctx
{-# NOINLINE withGCM #-}

-- | One shot function to GCM data without any incremental handling
encryptGCM :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
encryptGCM key iv header input = withGCM DirectionEncrypt key iv $ \ctx -> do
    output <- B.mallocByteString ciphertextLength

    -- consume the header as authenticated data
    when (headerLength > 0) $ do
        B.withBytePtr header $ \h ->
            checkRet "encryptupdate-header" (alloca $ \outl -> openssl_c_encryptupdate ctx nullPtr outl h (fromIntegral headerLength))

    -- consume the input data and, create output data + GCM tag
    alloca $ \ptrOutl ->
        B.withBytePtr input   $ \inp -> do
        withForeignPtr output $ \out -> do
            checkRet "encryptupdate-input" (openssl_c_encryptupdate ctx out ptrOutl inp (fromIntegral inputLength))
            encryptedLen <- peek ptrOutl
            checkRet "encryptfinal_ex" (openssl_c_encryptfinal_ex ctx (out `plusPtr` (fromIntegral encryptedLen)) ptrOutl)
            checkRet "ctx_ctrl_get_tag" (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_GET_TAG (fromIntegral gcmTagLength) (out `plusPtr` inputLength))
    return $ B.PS output 0 ciphertextLength
  where
        ciphertextLength = B.byteableLength input + gcmTagLength
        headerLength     = B.byteableLength header
        inputLength      = B.byteableLength input
{-# NOINLINE encryptGCM #-}

-- | One shot function to decrypt GCM data without any incremental handling
decryptGCM :: ByteString -> ByteString -> ByteString -> ByteString -> Maybe ByteString
decryptGCM key iv header input
    | inputLength < gcmTagLength = Nothing
    | otherwise                  = withGCM DirectionDecrypt key iv $ \ctx -> do
        output <- B.mallocByteString plaintextLength

        -- consume the header as authenticated data
        when (headerLength > 0) $ do
            B.withBytePtr header $ \h  ->
                checkRet "decryptupdate-header" (alloca $ \outl -> openssl_c_decryptupdate ctx nullPtr outl h (fromIntegral headerLength))

        -- consume the input data and, create output data + GCM tag
        B.withBytePtr input $ \inp ->
            withForeignPtr output $ \out ->
            alloca $ \ptrOutl -> do
                checkRet "decryptupdate-input" (openssl_c_decryptupdate ctx out ptrOutl inp (fromIntegral plaintextLength))
                checkRet "ctx_ctrl_set_tag" (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_SET_TAG (fromIntegral gcmTagLength) (inp `plusPtr` plaintextLength))
                r <- openssl_c_decryptfinal_ex ctx out ptrOutl
                if r == 0
                    then return Nothing -- validation failed
                    else return $ Just $ B.PS output 0 plaintextLength
  where
        plaintextLength = B.byteableLength input - gcmTagLength
        headerLength    = B.byteableLength header
        inputLength     = B.byteableLength input
{-# NOINLINE decryptGCM #-}

checkRet :: String -> IO CInt -> IO ()
checkRet n f = do
    r <- f
    if (r /= 1) then throwIO $ OpenSSLGcmError n else return ()

contextDuplicateTemp :: ForeignPtr a -> (Ptr a -> IO b) -> IO b
contextDuplicateTemp ctx f = do
    allocaBytes sizeofEVP $ \tmp -> do
        withForeignPtr ctx $ \old -> copyBytes tmp old sizeofEVP
        f tmp

contextNew :: (Ptr EVP_CIPHER_CTX -> IO ()) -> IO GCMCtx
contextNew f = do
    ptr <- mallocBytes sizeofEVP
    B.memset (castPtr ptr) 0 (fromIntegral sizeofEVP)
    f ptr
    newForeignPtr openssl_c_cipher_ctx_cleanup ptr

gcmTagLength :: Int
gcmTagLength = 16

sizeofEVP :: Int
sizeofEVP = (#const sizeof(EVP_CIPHER_CTX))

data EVP_CIPHER
data EVP_CIPHER_CTX

type KeyBuf = Ptr Word8

type IvBuf = Ptr Word8
type DataBuf = Ptr Word8
type OutputOffset = Ptr CInt
type InputLength = CInt

data ENGINE

nullEngine :: Ptr ENGINE
nullEngine = nullPtr

foreign import ccall unsafe "EVP_CIPHER_CTX_init"
    openssl_c_cipher_ctx_init :: Ptr EVP_CIPHER_CTX -> IO ()

foreign import ccall unsafe "&EVP_CIPHER_CTX_free"
    openssl_c_cipher_ctx_free :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

foreign import ccall unsafe "&EVP_CIPHER_CTX_cleanup"
    openssl_c_cipher_ctx_cleanup :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

foreign import ccall unsafe "EVP_CIPHER_CTX_ctrl"
    openssl_c_cipher_ctx_ctrl :: Ptr EVP_CIPHER_CTX -> CInt -> CInt -> Ptr a -> IO CInt

foreign import ccall unsafe "EVP_CIPHER_CTX_set_padding"
    openssl_c_cipher_ctx_set_padding :: Ptr EVP_CIPHER_CTX -> CInt -> IO CInt

foreign import ccall unsafe "EVP_CIPHER_CTX_set_key_length"
    openssl_c_cipher_ctx_set_key_length :: Ptr EVP_CIPHER_CTX -> CInt -> IO CInt

foreign import ccall unsafe "EVP_EncryptInit_ex"
    openssl_c_encryptinit_ex :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Ptr ENGINE -> KeyBuf -> IvBuf -> IO CInt

foreign import ccall unsafe "EVP_DecryptInit_ex"
    openssl_c_decryptinit_ex :: Ptr EVP_CIPHER_CTX -> Ptr EVP_CIPHER -> Ptr ENGINE -> KeyBuf -> IvBuf -> IO CInt

foreign import ccall unsafe "EVP_EncryptUpdate"
    openssl_c_encryptupdate :: Ptr EVP_CIPHER_CTX -> DataBuf -> OutputOffset -> DataBuf -> InputLength -> IO CInt

foreign import ccall unsafe "EVP_DecryptUpdate"
    openssl_c_decryptupdate :: Ptr EVP_CIPHER_CTX -> DataBuf -> OutputOffset -> DataBuf -> InputLength -> IO CInt

foreign import ccall unsafe "EVP_EncryptFinal_ex"
    openssl_c_encryptfinal_ex :: Ptr EVP_CIPHER_CTX -> DataBuf -> OutputOffset -> IO CInt

foreign import ccall unsafe "EVP_DecryptFinal_ex"
    openssl_c_decryptfinal_ex :: Ptr EVP_CIPHER_CTX -> DataBuf -> OutputOffset -> IO CInt

#ifdef OPENSSL_HAS_GCM
foreign import ccall unsafe "EVP_aes_256_gcm"
    openssl_c_aes_256_gcm :: IO (Ptr EVP_CIPHER)
#else
openssl_c_aes_256_gcm :: IO (Ptr EVP_CIPHER)
openssl_c_aes_256_gcm = return nullPtr
#endif

ctrl_GCM_SET_IVLEN, ctrl_GCM_GET_TAG, ctrl_GCM_SET_TAG :: CInt
#ifdef OPENSSL_HAS_GCM
ctrl_GCM_SET_IVLEN = (#const EVP_CTRL_GCM_SET_IVLEN)
ctrl_GCM_GET_TAG =  (#const EVP_CTRL_GCM_GET_TAG)
ctrl_GCM_SET_TAG =  (#const EVP_CTRL_GCM_SET_TAG)
#else
-- not sure if this is a good idea to hardcode it.
ctrl_GCM_SET_IVLEN = 0x9
ctrl_GCM_GET_TAG = 0x10
ctrl_GCM_SET_TAG = 0x11
#endif
