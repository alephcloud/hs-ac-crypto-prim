-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Hmac
#if defined(NATIVE)
( module PC.Crypto.Prim.Hmac.Native ) where import PC.Crypto.Prim.Hmac.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Hmac.OpenSSL ) where import PC.Crypto.Prim.Hmac.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Hmac.Sjcl ) where import PC.Crypto.Prim.Hmac.Sjcl
#else
#error "undefined backend"
#endif
