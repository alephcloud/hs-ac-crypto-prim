-- ------------------------------------------------------ --
-- Copyright (C) 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

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
