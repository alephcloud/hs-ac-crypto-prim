-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Sha
#if defined(NATIVE)
( module PC.Crypto.Prim.Sha.Native ) where import PC.Crypto.Prim.Sha.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Sha.OpenSSL ) where import PC.Crypto.Prim.Sha.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Sha.Sjcl ) where import PC.Crypto.Prim.Sha.Sjcl
#else
#error "undefined backend"
#endif
