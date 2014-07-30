-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Bn
#if defined(NATIVE)
( module PC.Crypto.Prim.Bn.Native ) where import PC.Crypto.Prim.Bn.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Bn.OpenSSL ) where import PC.Crypto.Prim.Bn.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Bn.Sjcl ) where import PC.Crypto.Prim.Bn.Sjcl
#else
#error "undefined backend"
#endif
