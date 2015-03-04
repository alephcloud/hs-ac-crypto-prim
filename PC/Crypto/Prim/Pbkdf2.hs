-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.

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
