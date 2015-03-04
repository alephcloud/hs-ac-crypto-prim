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
    ( encryptInitGCM
    , decryptInitGCM
    , encryptGCM
    , decryptGCM
    ) where

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER > 0x10001000
#define OPENSSL_HAS_PBKDF2
#define OPENSSL_HAS_GCM
#endif

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils (copyBytes)
import Foreign.C.Types
import Foreign.C.String (withCString)
import Foreign.Storable
import Data.Word
import Data.ByteString
import qualified Data.ByteString.Internal as B
import qualified Data.Byteable as B
import System.IO.Unsafe

type GCMCtx = ForeignPtr EVP_CIPHER_CTX

encryptInitGCM key iv = initGCM DirectionEncrypt
decryptInitGCM key iv = initGCM DirectionDecrypt

data Direction = DirectionEncrypt | DirectionDecrypt

initGCM :: Direction -> ByteString -> ByteString -> Either String GCMCtx
initGCM direction key iv = unsafePerformIO $ do
    cipher <- openssl_c_aes_256_gcm
    if cipher == nullPtr
        then return $ Left "openssl doesn't have a GCM cipher"
        else do
            fptr <- contextNew
            withForeignPtr fptr $ \ctx    ->
                B.withBytePtr key $ \keyPtr ->
                B.withBytePtr iv  $ \ivPtr  -> do
                    checkRet (openssl_c_encryptinit_ex ctx cipher nullEngine nullPtr nullPtr)
                    checkRet (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_SET_IVLEN 12 nullPtr)
                    case direction of
                        DirectionEncrypt -> openssl_c_encryptinit_ex ctx nullPtr nullEngine keyPtr ivPtr
                        DirectionDecrypt -> openssl_c_decryptinit_ex ctx nullPtr nullEngine keyPtr ivPtr
            return $ Right fptr
{-# NOINLINE initGCM #-}

-- | One shot function to  GCM data without any incremental handling
encryptGCM :: GCMCtx -> ByteString -> ByteString -> ByteString
encryptGCM iniCtx header input = unsafePerformIO $ contextDuplicateTemp iniCtx $ \ctx -> do
    output <- B.mallocByteString ciphertextLength

    -- consume the header as authenticated data
    B.withBytePtr header $ \h  ->
        checkRet (alloca $ \outl -> openssl_c_encryptupdate ctx nullPtr outl h (fromIntegral headerLength))

    -- consume the input data and, create output data + GCM tag
    alloca $ \ptrOutl ->
        B.withBytePtr input   $ \inp -> do
        withForeignPtr output $ \out -> do
            checkRet (openssl_c_encryptupdate ctx out ptrOutl inp (fromIntegral inputLength))
            encryptedLen <- peek ptrOutl
            checkRet (openssl_c_encryptfinal_ex ctx out ptrOutl)
            checkRet (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_GET_TAG (fromIntegral gcmTagLength) (out `plusPtr` fromIntegral encryptedLen))
    return $ B.PS output 0 ciphertextLength
  where ciphertextLength = B.byteableLength input + gcmTagLength
        headerLength     = B.byteableLength header
        inputLength      = B.byteableLength input
{-# NOINLINE encryptGCM #-}

-- | One shot function to decrypt GCM data without any incremental handling
decryptGCM :: GCMCtx -> ByteString -> ByteString -> Maybe ByteString
decryptGCM iniCtx header input
    | inputLength < gcmTagLength = Nothing
    | otherwise                  = unsafePerformIO $ contextDuplicateTemp iniCtx $ \ctx -> do
        output <- B.mallocByteString plaintextLength

        -- consume the header as authenticated data
        B.withBytePtr header $ \h  ->
            checkRet (alloca $ \outl -> openssl_c_decryptupdate ctx nullPtr outl h (fromIntegral headerLength))

        -- consume the input data and, create output data + GCM tag
        B.withBytePtr input $ \inp ->
            withForeignPtr output $ \out ->
            alloca $ \ptrOutl -> do
                checkRet (openssl_c_decryptupdate ctx out ptrOutl inp (fromIntegral plaintextLength))
                checkRet (openssl_c_cipher_ctx_ctrl ctx ctrl_GCM_SET_TAG (fromIntegral gcmTagLength) (inp `plusPtr` plaintextLength))
                r <- openssl_c_decryptfinal_ex ctx out ptrOutl
                if r == 0
                    then return Nothing -- validation failed
                    else return $ Just $ B.PS output 0 plaintextLength
  where plaintextLength = B.byteableLength input - gcmTagLength
        headerLength    = B.byteableLength header
        inputLength     = B.byteableLength input
{-# NOINLINE decryptGCM #-}

{-
aeadGCM :: Direction -> ByteString -> GCMCtx -> GCMCtx
aeadGCM direction header oldCtx = unsafePerformIO $ do
    contextDuplicate oldCtx $ \ctx ->
        B.withBytePtr header $ \h  ->
            case direction of
                DirectionEncrypt -> checkRet (alloca $ \outl -> openssl_c_encryptupdate ctx nullPtr outl h (fromIntegral $ B.byteableLength header))
                DirectionDecrypt -> checkRet (alloca $ \outl -> openssl_c_decryptupdate ctx nullPtr outl h (fromIntegral $ B.byteableLength header))
-}

checkRet :: IO CInt -> IO ()
checkRet f = do
    _ <- f -- TODO on -1, throw an error
    return ()

{-
contextDuplicateRet ctx f = do
    fptr <- contextNew
    a <- withForeignPtr ctx $ \old -> withForeignPtr fptr $ \new -> do
        copyBytes new old sizeofEVP
        f new
    return (a, fptr)

contextDuplicate ctx f = do
    fptr <- contextNew
    () <- withForeignPtr ctx $ \old -> withForeignPtr fptr $ \new -> do
        copyBytes new old sizeofEVP
        f new
    return fptr
-}

contextDuplicateTemp ctx f = do
    allocaBytes sizeofEVP $ \tmp -> do
        withForeignPtr ctx $ \old -> copyBytes tmp old sizeofEVP
        f tmp
    
contextNew = do
    fptr <- mallocBytes sizeofEVP >>= newForeignPtr openssl_c_cipher_ctx_free
    addForeignPtrFinalizer openssl_c_cipher_ctx_cleanup fptr
    return fptr

gcmTagLength = 16

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
