{-# LANGUAGE UnicodeSyntax #-}

module TWC.Crypto.Codec
( Code64(..)
, Code16(..)
) where

-- -------------------------------------------------------------------------- --
-- * Base64Url serialization

class Code64 α where
    to64 ∷ α → String
    from64 ∷ String → Either String α

-- -------------------------------------------------------------------------- --
-- * Hex serialization

class Code16 α where
    to16 ∷ α → String
    from16 ∷ String → Either String α

