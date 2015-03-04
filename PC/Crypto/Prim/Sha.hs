-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

{-# LANGUAGE CPP #-}

module PC.Crypto.Prim.Sha
#if defined(NATIVE)
( module PC.Crypto.Prim.Sha.Native, pSha512_256 ) where
import PC.Crypto.Prim.Sha.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Sha.OpenSSL, pSha512_256 ) where
import PC.Crypto.Prim.Sha.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Sha.Sjcl, pSha512_256 ) where
import PC.Crypto.Prim.Sha.Sjcl
#else
#error "undefined backend"
#endif

import PC.Bytes.Utils
import PC.Bytes.ByteArray
import PC.Bytes.ByteArrayL

pSha512_256 :: Parser (ByteArrayL Sha512_256Length)
pSha512_256 = pTakeBytesL <?> "pSha512_256"
