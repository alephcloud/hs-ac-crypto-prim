-- Copyright (c) 2013-2015 PivotCloud, Inc.
--
-- PC.Crypto.Prim.Ecc.Ops
--
-- Please feel free to contact us at licensing@pivotmail.com with any
-- contributions, additions, or other feedback; we would love to hear from
-- you.
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may
-- not use this file except in compliance with the License. You may obtain a
-- copy of the License at http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations
-- under the License.
--
-- |
-- Module      : PC.Crypto.Prim.Ecc.Ops
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : Apache-2, see LICENSE file of the package
-- Maintainer  : licensing@pivotmail.com
--
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
