-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
-- |
-- Module      : PC.Crypto.SearchableEncryption
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : All Right Reserved
-- Maintainer  : support@pivotmail.com
--
{-# LANGUAGE BangPatterns #-}
module PC.Crypto.SearchableEncryption
    (
    -- * various types
      Message
    , KeyWord
    , KeyWordContext
    , Bits
    , Secret
    , EncryptedKeyWord
    , SearchCapability
    , SearchCapabilities
    , Flag
    , EncryptedLogEntry
    -- * encrypt and decrypt log for a specific audit server
    , encryptLogEntry
    , encryptLogEntryWithR
    , decryptLogEntry
    , decryptMessage
    , decryptMany
    , filterLog
    -- * audit escrow agent functions
    , makeSearchCapability
    , makeSearchCapabilityFor

    -- * basic building blocks
    , h
    , bxor
    ) where

-- Searchable Encryption library
--
-- Implementation based on the paper:
--  "Building an Encrypted and Searchable Audit Log"
--
-- This implementation chose:
-- * use symmetric cipher
-- * to encrypt message using AES 128 bits, in CTR mode
-- * HMAC-SHA512 as a Keyed PRF
--
--

import Control.Arrow
import Control.DeepSeq
import Crypto.Cipher
import Crypto.Cipher.Types (KeySizeSpecifier(..))
import Crypto.Hash
import Crypto.Random
import Data.Maybe
import Data.List (find)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable
import Data.Bits (xor)

import Debug.Trace

-- BEWARE:
-- KeyedPRF need to provide an output size equal or greater than
-- the required bytes to initialize a key for SymCipher + size flag
--
-- SHA256 (32 bytes) > AES128 (16 bytes)
--

type KeyedPRF = ByteString -- key
             -> ByteString -- msg
             -> HMAC SHA256
type SymCipher = AES128

type SymKey  = ByteString
type Message = ByteString
type KeyWord = ByteString
type KeyWordContext = ByteString
type Bits    = ByteString
type Secret  = ByteString
type Flag    = ByteString
type EncryptedKeyWord = ByteString
type EncryptedKeyWordContext = ByteString
type SearchCapability = ByteString
type SearchCapabilities = [SearchCapability]

-- | a tuple of the IV for the CTR cipher, the encrypted message
-- the random r bit array and the list of encrypted keywords
type EncryptedLogEntry = (Message, Bits, [(EncryptedKeyWord, [EncryptedKeyWordContext])])

encryptSym ctx v = ctrCombine ctx nullIV v

encryptLogEntry :: CPRG g
                => g         -- ^ the random bytes generator
                -> Secret    -- ^ the secret on this audit server
                -> Flag      -- ^ the constant flag
                -> Message   -- ^ message to encrypt in the log
                -> [(KeyWord, [KeyWordContext])] -- ^ keywords associated with this message
                -> (EncryptedLogEntry, g)
encryptLogEntry rng0 s flag msg keywords = deepseq ekeywords $ deepseq emsg $ ((emsg, r, ekeywords), rng2)
  where
        ctx         :: SymCipher
        ctx         = cipherInit key
        (key, rng1) = generateRandomKey rng0
        (r,   rng2) = cprgGenerate 16 rng1
        emsg        = encryptSym ctx msg
        ekeywords   = map (\(w, ctxs) -> (encryptKeyword w, map (encryptSym ctx) ctxs)) keywords
        encryptKeyword w = deepseq b c
          where a = h s w -- ℋ (keyed by s) of w
                b = h a r -- ℋ (keyed by a) of r
                c = b `bxor` (flag `B.append` toBytes key)

-- | Encrypt a message with keywords on a specific audit server
--
-- similar to previous call except with an explicit r.
encryptLogEntryWithR :: CPRG g
                     => g         -- ^ the random bytes generator
                     -> Secret    -- ^ the secret on this audit server
                     -> Flag      -- ^ the constant flag
                     -> ByteString -- ^ the r
                     -> Message   -- ^ message to encrypt in the log
                     -> [(KeyWord, [KeyWordContext])] -- ^ keywords associated with this message
                     -> (EncryptedLogEntry, g)
encryptLogEntryWithR rng0 s flag r msg keywords = deepseq ekeywords $ deepseq emsg $ ((emsg, r, ekeywords), rng1)
  where
        ctx         :: SymCipher
        ctx         = cipherInit key
        (key, rng1) = generateRandomKey rng0
        --key = trace (show $ toBytes key_) key_
        emsg        = encryptSym ctx msg
        ekeywords   = map (\(w, ctxs) -> (encryptKeyword w, map (encryptSym ctx) ctxs)) keywords
        encryptKeyword w = deepseq b c
          where a = h s w -- ℋ (keyed by s) of w
                b = h a r -- ℋ (keyed by a) of r
                c = b `bxor` (flag `B.append` toBytes key)

-- | the audit escrow agent grant from the many secrets and a keyword
-- a search capabilities for each servers.
--    ⅆ_w = [ ⅆ_w_j ] for 1 <= j <= t
--
makeSearchCapability :: [Secret] -> KeyWord -> SearchCapabilities
makeSearchCapability secrets keyword =
    map (flip makeSearchCapabilityFor keyword) secrets

-- | the audit escrow agent grant from a secret and a keyword
-- a search capability for
--
-- This is just a the keyword prf'ed with the secret.
--    ⅆ_w_j = ℋ (s_j, w)
--
makeSearchCapabilityFor :: Secret -> KeyWord -> ByteString
makeSearchCapabilityFor secret keyword = toBytes $ h secret keyword

-- | use the search capability to maybe output the message.
--
-- If our 'SearchCapability' is able to match at least one keyword, then
-- we're able to recover the key K that was used to encrypt the message,
-- and thus the message itself.
decryptLogEntry :: Flag              -- ^ const Flag bitarray
                -> SearchCapability  -- ^ our Search capability for a specific server given by the audit escrow agent
                -> EncryptedLogEntry -- ^ the log entry
                -> Maybe Message     -- ^ maybe the decrypted message if keyword match
decryptLogEntry flag searchCap (emsg, r, ekws) =
    -- long version to make clear what we're doing here,
    -- instead of using fmap and Maybe monad style.
    case find (B.isPrefixOf flag) mks of
        Nothing -> Nothing
        Just b  -> let key = B.drop (B.length flag) b
                    in decryptMessage key emsg
  where p   = toBytes $ h searchCap r
        mks = map (bxor p . fst) ekws

-- | return the decrypted message and possibly the matching key
decryptMessage :: SymKey -> ByteString -> Maybe Message
decryptMessage keyBS emsg =
    case makeKey $ B.take 16 keyBS of
        Left _    -> Nothing -- error ("invalid key: " ++ show keyBS ++ " (" ++ show (B.length keyBS) ++ ")")
        Right key -> Just $ ctrCombine (cipherInit key :: SymCipher) nullIV emsg

-- | decrypt many bytestring.
--
-- TODO: probably a good idea to not restart the IV after use, but continue increasing.
decryptMany :: SymKey -> [ByteString] -> [ByteString]
decryptMany keyBS l =
    case makeKey $ B.take 16 keyBS of
        Left _    -> []
        Right key ->
            let ctx = cipherInit key :: SymCipher
             in map (ctrCombine ctx nullIV) l

-- | Filter the encrypted log with everything that match
--
-- the lazy way.
filterLog :: Flag                -- ^ const Flag bitarray
          -> SearchCapability    -- ^ our Search capability given by the audit escrow agent
          -> [EncryptedLogEntry] -- ^ a list of encrypted logs
          -> [Message]           -- ^ matched messages
filterLog flag searchCap logs =
    catMaybes $ map (decryptLogEntry flag searchCap) logs

------------------------------------------------------------------------
-- paper related definition
------------------------------------------------------------------------

-- | ℋ  is a keyed pseudo random function (PRF), as described in the
-- paper as H.
--
-- In this instance we use HMAC-SHA1 (forced by the signature)
h :: ByteString -> ByteString -> ByteString
h s m = toBytes $ keyedprf s m
  where keyedprf :: KeyedPRF
        keyedprf = hmac

------------------------------------------------------------------------
-- utils
------------------------------------------------------------------------

-- | Generate a random key associated with a specific cipher.
-- if the cipher take multiple sizes, the strongest size will be
-- automatically chosen
generateRandomKey :: (CPRG g, Cipher cipher) => g -> (Key cipher, g)
generateRandomKey = genKey undefined
  where genKey :: (CPRG g, Cipher c) => c -> g -> (Key c, g)
        genKey cipher rng =
            let sz = case cipherKeySize cipher of
                        KeySizeRange _ high -> high
                        KeySizeFixed v      -> v
                        KeySizeEnum l       -> maximum l
             in first (either (error . show) id . makeKey) $ cprgGenerate sz rng

-- | Bytestring xor.
bxor :: ByteString -> ByteString -> ByteString
bxor a b = B.pack $ B.zipWith xor (B.copy a) (B.copy b)
