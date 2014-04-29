{-# LANGUAGE CPP #-}
module TWC.Crypto.Sha
#if defined(NATIVE)
( module TWC.Crypto.Sha.Native ) where import TWC.Crypto.Sha.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Sha.OpenSSL ) where import TWC.Crypto.Sha.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Sha.Sjcl ) where import TWC.Crypto.Sha.Sjcl
#else
#error "undefined backend"
#endif
