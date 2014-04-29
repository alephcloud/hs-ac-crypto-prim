{-# LANGUAGE CPP #-}
module TWC.Crypto.Ecc.Ops
#if defined(NATIVE)
( module TWC.Crypto.Ecc.Native ) where import TWC.Crypto.Ecc.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Ecc.OpenSSL ) where import TWC.Crypto.Ecc.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Ecc.Sjcl ) where import TWC.Crypto.Ecc.Sjcl
#else
#error "undefined backend"
#endif
