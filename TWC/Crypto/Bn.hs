{-# LANGUAGE CPP #-}
module TWC.Crypto.Bn
#if defined(NATIVE)
( module TWC.Crypto.Bn.Native ) where import TWC.Crypto.Bn.Native
#elif defined(OPENSSL)
( module TWC.Crypto.Bn.OpenSSL ) where import TWC.Crypto.Bn.OpenSSL
#elif defined(SJCL)
( module TWC.Crypto.Bn.Sjcl ) where import TWC.Crypto.Bn.Sjcl
#else
#error "undefined backend"
#endif
