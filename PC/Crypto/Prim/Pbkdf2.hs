-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module PC.Crypto.Prim.Pbkdf2
#if defined(NATIVE)
( module PC.Crypto.Prim.Pbkdf2.Native ) where import PC.Crypto.Prim.Pbkdf2.Native
#elif defined(OPENSSL)
( module PC.Crypto.Prim.Pbkdf2.OpenSSL ) where import PC.Crypto.Prim.Pbkdf2.OpenSSL
#elif defined(SJCL)
( module PC.Crypto.Prim.Pbkdf2.Sjcl ) where import PC.Crypto.Prim.Pbkdf2.Sjcl
#else
#error "undefined backend"
#endif
