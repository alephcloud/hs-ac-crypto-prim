-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeOperators #-}

{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Aes
#if defined(NATIVE)
( module PC.Crypto.Prim.Aes.Native, pAesIV, pAes256mac ) where
import PC.Crypto.Prim.Aes.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Aes.OpenSSL, pAesIV, pAes256mac ) where
import PC.Crypto.Prim.Aes.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Aes.Sjcl, pAesIV, pAes256mac ) where
import PC.Crypto.Prim.Aes.Sjcl
#else
#error "undefined backend"
#endif

import Control.Applicative
import PC.Bytes.Utils
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL
import PC.Crypto.Prim.Sha (pSha512_256, sha512_256Length, Sha512_256Length)

pAesIV :: (BytesL AesIV) => Parser (ByteArrayImpl AesIV) AesIV
pAesIV = pTakeBytesL <?> "pAesIV"

pAes256mac :: (BytesL AesIV) => Parser (ByteArrayImpl AesIV) (AesIV, (ByteArrayImpl AesIV), ByteArrayL (ByteArrayImpl AesIV) Sha512_256Length)
pAes256mac = (,,)
    <$> pAesIV
    <*> pTakeExcept sha512_256Length
    <*> pSha512_256
    <?> "pAes256mac"
