{-# LANGUAGE CPP #-}
module TWC.Crypto.Ecc.Ops
#if defined(ECC_NATIVE)
( module TWC.Crypto.Ecc.Native ) where import TWC.Crypto.Ecc.Native
#elif defined(ECC_OPENSSL)
( module TWC.Crypto.Ecc.OpenSSL ) where import TWC.Crypto.Ecc.OpenSSL
#elif defined(ECC_SJCL)
( module TWC.Crypto.Ecc.Sjcl ) where import TWC.Crypto.Ecc.Sjcl
#else
#error "undefined ECC backend"
#endif
