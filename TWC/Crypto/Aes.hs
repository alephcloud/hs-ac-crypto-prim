-- ------------------------------------------------------ --
-- Copyright © 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE CPP #-}
module TWC.Crypto.Aes
#if defined(NATIVE)
( module TWC.Crypto.Aes.Native ) where import TWC.Crypto.Aes.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Aes.OpenSSL ) where import TWC.Crypto.Aes.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Aes.Sjcl ) where import TWC.Crypto.Aes.Sjcl
#else
#error "undefined backend"
#endif
