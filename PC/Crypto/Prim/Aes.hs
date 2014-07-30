-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Aes
#if defined(NATIVE)
( module PC.Crypto.Prim.Aes.Native ) where import PC.Crypto.Prim.Aes.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Aes.OpenSSL ) where import PC.Crypto.Prim.Aes.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Aes.Sjcl ) where import PC.Crypto.Prim.Aes.Sjcl
#else
#error "undefined backend"
#endif
