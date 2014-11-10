-- ------------------------------------------------------ --
-- Copyright (C) 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

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
