-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

{-# LANGUAGE CPP #-}

module PC.Crypto.Prim.Aes
#if defined(NATIVE)
( module PC.Crypto.Prim.Aes.Native ) where
import PC.Crypto.Prim.Aes.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Aes.OpenSSL ) where
import PC.Crypto.Prim.Aes.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Aes.Sjcl ) where
import PC.Crypto.Prim.Aes.Sjcl
#else
#error "undefined backend"
#endif
