-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

{-# LANGUAGE CPP #-}

module PC.Crypto.Prim.Ecc.Ops
#if defined(ECC_NATIVE)
( module PC.Crypto.Prim.Ecc.Native ) where import PC.Crypto.Prim.Ecc.Native
#elif defined(ECC_OPENSSL)
( module PC.Crypto.Prim.Ecc.OpenSSL ) where import PC.Crypto.Prim.Ecc.OpenSSL
#elif defined(ECC_SJCL)
( module PC.Crypto.Prim.Ecc.Sjcl ) where import PC.Crypto.Prim.Ecc.Sjcl
#else
#error "undefined ECC backend"
#endif
