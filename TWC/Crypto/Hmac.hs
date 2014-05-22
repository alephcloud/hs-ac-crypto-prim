-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module TWC.Crypto.Hmac
#if defined(NATIVE)
( module TWC.Crypto.Hmac.Native ) where import TWC.Crypto.Hmac.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Hmac.OpenSSL ) where import TWC.Crypto.Hmac.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Hmac.Sjcl ) where import TWC.Crypto.Hmac.Sjcl
#else
#error "undefined backend"
#endif
