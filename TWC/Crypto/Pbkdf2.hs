-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module TWC.Crypto.Pbkdf2
#if defined(NATIVE)
( module TWC.Crypto.Pbkdf2.Native ) where import TWC.Crypto.Pbkdf2.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Pbkdf2.OpenSSL ) where import TWC.Crypto.Pbkdf2.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Pbkdf2.Sjcl ) where import TWC.Crypto.Pbkdf2.Sjcl
#else
#error "undefined backend"
#endif
