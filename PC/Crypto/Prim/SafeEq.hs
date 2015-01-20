-- Copyright (c) 2013-2014 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
-- |
-- Module      : PC.Crypto.Prim.SafeEq
-- Copyright   : (c) 2013-2014 PivotCloud, Inc
-- License     : All Right Reserved
-- Maintainer  : support@pivotmail.com
--
-- another Eq class supposed to defined time constant equal operation
--
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module PC.Crypto.Prim.SafeEq (SafeEq(..)) where

import PC.Bytes.ByteArray
import Data.Byteable (constEqBytes)
import Data.ByteString (ByteString)

class SafeEq a where
    safeEq :: a -> a -> Bool

instance SafeEq ByteString where
    safeEq = constEqBytes
