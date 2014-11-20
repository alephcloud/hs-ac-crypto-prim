-- ------------------------------------------------------ --
-- Copyright (C) 2014 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

module PC.Crypto.Prim.Pbkdf2
    ( pbkdf2Sha512
    ) where

import Crypto.KDF.PBKDF2
import Crypto.Hash (SHA512(..))
import Data.ByteString (ByteString)

pbkdf2Sha512 :: ByteString -- ^ password
             -> ByteString -- ^ salt
             -> Int        -- ^ number of rounds
             -> Int        -- ^ size of result in bytes
             -> ByteString
pbkdf2Sha512 password salt iter outLen = generate (prfHMAC SHA512) $ Parameters password salt iter outLen
