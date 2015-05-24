-- Copyright (c) 2013-2015 PivotCloud, Inc. All Rights Reserved.
--
-- NOTICE: The dissemination, reproduction, or copying of this file and the
-- information contained herein, in any medium, is strictly forbidden.
--
-- The intellectual property and technical concepts contained herein are
-- proprietary to PivotCloud and are protected by U.S. and Foreign law.
--
-- |
-- Module      : PC.Crypto.PVSS
-- Copyright   : (c) 2013-2015 PivotCloud, Inc
-- License     : All Right Reserved
-- Maintainer  : support@pivotmail.com
--
-- Implementation of the Public Verifiable Secret Scheme
-- based on Berry Schoenmakers's paper:
--
--	<http://www.win.tue.nl/~berry/papers/crypto99.pdf>
--
-- Other secret sharing scheme for references:
--
--    <eprint.iacr.org/2010/495.pdf>
--
-- others useful references:
--
--    <https://en.wikipedia.org/wiki/Verifiable_secret_sharing>
--    <https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing>
--
-- This implementation used the 'u = g^random' scheme
-- described in section 4 to actually compute the secret, instead of
-- recovering g^secret from the section 3 scheme.
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
module PC.Crypto.PVSS
    ( Threshold
    , ExtraGen(..)
    , Circuit(..)
    , circuitThreshold
    , SecretSharesLocked
    , EncryptedShare(..)
    , DecryptedShare(..)
    , Commitment
    , pvssCreatePolynomial
    , pvssEscrow
    , pvssEscrowWith
    , pvssVerifyEncryptedShares
    , pvssVerifyEncryptedShare
    , pvssVerifyDecryptedShare
    , pvssShareCreate
    , pvssShareDecrypt
    , pvssRecoverNoVerify
    , pvssRecover
    , pvssDeriveKey
    , DLEQ(..)
    , Proof(..)
    , proofGenerate
    , proofVerify
    ) where

import Control.Monad
import Control.Applicative
import Control.DeepSeq
import PC.Bytes.ByteArray (Bytes(..))
import PC.Crypto.Key
import PC.Crypto.DHDS
import PC.Crypto.KDF
import PC.Crypto.Prim.Sha
import PC.Crypto.Prim.Class (DhSecret(..))
import PC.Crypto.Imports
import Data.Bits
import Data.Proxy
import qualified Data.ByteString.UTF8 as UTF8 (fromString)

import Prelude hiding (pi)

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Data.List (foldl')

-- uncomment the first equation to conduct costly internal check
-- False mean there's no error
internalCheck :: Bool -> Bool
--internalCheck r = r
internalCheck = const False

newtype Commitment point = Commitment { unCommitment :: point }
    deriving (Show,Eq,Bytes,ToACN,FromACN,NFData)

type Threshold = Integer

newtype ExtraGen point = ExtraGen point
    deriving (Show,Eq,Bytes,ToACN,FromACN,NFData)

-- | Circuit
data Circuit alg scalar point = Circuit
    { circuitShareGenerator :: !(ExtraGen point)
    , circuitSecretLocked   :: !(SecretSharesLocked alg)
    , circuitCommitments    :: ![Commitment point]
    , circuitShares         :: ![EncryptedShare point scalar]
    } deriving (Show,Eq,Generic)

instance (ToACN scalar, ToACN point) => ToACN (Circuit alg scalar point) where
    toACN (Circuit a b c d) = toACN (a,b,c,d)
instance (FromACN scalar, FromACN point) => FromACN (Circuit alg scalar point) where
    fromACN l =
        case fromACN l of
            Left err             -> Left ("Circuit: " ++ err)
            Right ((a,b,c,d),l') -> Right (Circuit a b c d, l')

circuitThreshold :: Circuit alg scalar point -> Integer
circuitThreshold = fromIntegral . length . circuitCommitments

-- | A secret locked to shares
newtype SecretSharesLocked alg = SecretSharesLocked ByteString
    deriving (Show,Eq,Generic)
instance NFData (SecretSharesLocked a) where
    rnf x = x `seq` ()
instance Bytes (SecretSharesLocked alg) where
    fromBytes = Right . SecretSharesLocked
    toBytes (SecretSharesLocked bs) = bs
instance ToACN (SecretSharesLocked alg) where
    toACN (SecretSharesLocked bs) = [AcnBytes bs]
instance FromACN (SecretSharesLocked alg) where
    fromACN l = case fromACN l of
                    Left err      -> Left ("SecretSharesLocked: " ++ err)
                    Right (bs, l') -> Right (SecretSharesLocked bs, l')

-- | Represent one of the share in the PVSS scheme necessary to reconstruct a secret.
-- It's tied to a private key
data EncryptedShare point scalar = EncryptedShare
    { shareID           :: !ShareId
    , shareEncryptedVal :: !point                -- ^ encrypted by participant public key
    , shareValidProof   :: !(Proof point scalar) -- ^ proof it's a valid share
    } deriving (Show,Eq,Generic)

instance (NFData point, NFData scalar) => NFData (EncryptedShare point scalar)

instance (ToACN point, ToACN scalar) => ToACN (EncryptedShare point scalar) where
    toACN (EncryptedShare sid eVal proof) = toACN (sid, eVal, proof)
instance (FromACN point, FromACN scalar) => FromACN (EncryptedShare point scalar) where
    fromACN l = case fromACN l of
                    Left err                       -> Left ("EncryptedShare " ++ err)
                    Right ((sid, eVal, proof), l') -> Right (EncryptedShare sid eVal proof, l')

-- | When recovering a secret, this is the contribution each participant make
-- from the EncryptedShare
data DecryptedShare point scalar = DecryptedShare
    { decryptedShareID    :: !ShareId
    , shareDecryptedVal   :: !point                -- ^ decrypted share
    , decryptedValidProof :: !(Proof point scalar) -- ^ proof the decryption is valid
    } deriving (Show,Eq)

instance (ToACN point, ToACN scalar) => ToACN (DecryptedShare point scalar) where
    toACN (DecryptedShare sid eVal proof) = toACN (sid, eVal, proof)
instance (FromACN point, FromACN scalar) => FromACN (DecryptedShare point scalar) where
    fromACN l = case fromACN l of
                    Left err                       -> Left ("EncryptedShare " ++ err)
                    Right ((sid, eVal, proof), l') -> Right (DecryptedShare sid eVal proof, l')

type ShareId = Integer

publicKeyMulFlip :: ArithKey scalar point => point -> scalar -> point
publicKeyMulFlip p s = publicKeyMul s p

-- | generate a random polynomial of degree t where
-- the secret is the weakest coefficient secret
pvssCreatePolynomial :: ArithKey scalar point => Threshold -> IO (Polynomial scalar)
pvssCreatePolynomial t =
    polyRandom (fromIntegral t)

-- | Derive a PVSS key from an answer to a question
--
-- The question is used as salt for the KDF scheme,
-- while the answer is slow hashed as the secret
-- of the KDF scheme.
pvssDeriveKey :: (KDF kdfAlg, ArithKey secretKey publicKey)
              => Proxy kdfAlg -- ^ the type of KDF algorithm used
              -> String    -- ^ the question
              -> String    -- ^ the answer associated
              -> secretKey -- ^ the derived secret key
pvssDeriveKey proxy question answer = doDeriveWithWitness (keyFromNum 1)
  where
        salt   = KDFSalt $ UTF8.fromString question
        secret = KDFSecret $ UTF8.fromString answer

        doErr e = error ("pvssDeriveKey: internal error assumption : " ++ e)

        doDeriveWithWitness :: ArithKey secretKey publicKey => secretKey -> secretKey
        doDeriveWithWitness witness = either doErr id $ fromBytes (kdf proxy secret salt len)
          where len = B.length $ toBytes witness

-- | Prepare a secret into public encrypted shares for distributions using the PVSS scheme
--
-- returns:
--  * the encrypted secret which is locked symettrically to the DH-secret (g^random)
--  * the list of public commitments (Cj) to the scheme
--  * The encrypted shares that should be distributed to each partipants.
pvssEscrow :: (DhDerivedSymmetric alg, ArithKey scalar point)
           => Threshold        -- ^ PVSS scheme configuration n/t threshold
           -> [point]          -- ^ Participants public keys
           -> ByteString       -- ^ The secret that will be distributed
           -> IO (Circuit alg scalar point)
pvssEscrow t pubs sigma = do
    poly <- pvssCreatePolynomial t
    gen  <- publicKeyFromSecret <$> keyGenerate
    pvssEscrowWith poly (ExtraGen gen) pubs sigma

-- | Escrow with a given polynomial
pvssEscrowWith :: (DhDerivedSymmetric alg, ArithKey scalar point)
               => Polynomial scalar -- ^ A chosen polynomial
               -> ExtraGen point    -- ^ Extra generator
               -> [point]           -- ^ Participants public keys
               -> ByteString        -- ^ The secret that will be distributed
               -> IO (Circuit alg scalar point)
pvssEscrowWith poly@(Polynomial polyCoeffs@(secret:_)) extraGen@(ExtraGen g) pubs sigma = do
    let gS = publicKeyToDhSecret (publicKeyFromSecret secret)
        u  = pvssEncryptSecret gS sigma

    -- create commitments Cj = g ^ aj
    let commitments = map (\c -> Commitment (g `publicKeyMulFlip` c)) polyCoeffs

    -- create the encrypted shares Yi + proof
    encryptedShares <- forM (zip [1..] pubs) $ uncurry (pvssShareCreate extraGen poly commitments)

    return $ Circuit
            { circuitShareGenerator = extraGen
            , circuitSecretLocked   = u
            , circuitCommitments    = commitments
            , circuitShares         = encryptedShares
            }
pvssEscrowWith _ _ _ _ =
    error "pvssEscrowWith: invalid empty polynomial"

-- | Create share out of a specific polynomial P(x)
--
-- the secret being escrow to this public key is the evaluation of the polynomial P(x) at
-- for a specific 'x' value. In this case, the Share ID is the 'x' value.
pvssShareCreate :: ArithKey scalar point
                => ExtraGen point
                -> Polynomial scalar
                -> [Commitment point]
                -> ShareId
                -> point
                -> IO (EncryptedShare point scalar)
pvssShareCreate (ExtraGen g) poly commitments shareId pub = do
    let pEvaled_i = polyEval poly (keyFromNum $ shareId)
        yi        = pub `publicKeyMulFlip` pEvaled_i
        xi        = createXi shareId commitments
    challenge <- keyGenerate
    let dleq  = DLEQ { dleq_g1 = g, dleq_h1 = xi, dleq_g2 = pub, dleq_h2 = yi }
        proof = proofGenerate "share-create" challenge pEvaled_i (proofParams dleq)
        --validated = proofVerify pp proof
        --validated2 = xi == dlogGroup grp (gen g `opSmul` pEvaled_i)

    return $ EncryptedShare shareId yi proof -- (assert (validated && validated2) proof)

-- | Decrypt a share using the participant public key
--
-- A participant wanting to contribute his share to recover the
-- secret will use this to create a DecryptedShare structure
-- (the decrypted share plus a proof of valid decryption)
pvssShareDecrypt :: ArithKey scalar point
                 => KeyPair scalar point
                 -> EncryptedShare point scalar
                 -> IO (DecryptedShare point scalar)
pvssShareDecrypt (KeyPair xi yi) (EncryptedShare sid _Yi _) = do
    challenge <- keyGenerate
    let dleq  = DLEQ curveGenerator yi si _Yi
        proof = proofGenerate "share-decrypt" challenge xi (proofParams dleq)
    return $ DecryptedShare sid si proof
  where xiInv = keyInverse xi
        si    = _Yi `publicKeyMulFlip` xiInv

-- | simple helper to call 'verifyEncryptedShare' on all
-- available encrypted shares, and return if all of they
-- are verified correctly.
pvssVerifyEncryptedShares :: ArithKey scalar point
                          => ExtraGen point
                          -> [Commitment point]
                          -> [(EncryptedShare point scalar, point)]
                          -> Bool
pvssVerifyEncryptedShares extraGen commitments allShares =
    and $ map (pvssVerifyEncryptedShare extraGen commitments) allShares

-- | Verify that a publically available encrypted share is valid.
--
-- Anyone can publically verify that the available values are valid
-- provided the public commitments and an encrypted share.
pvssVerifyEncryptedShare :: ArithKey scalar point
                         => ExtraGen point
                         -> [Commitment point]
                         -> (EncryptedShare point scalar, point)
                         -> Bool
pvssVerifyEncryptedShare (ExtraGen g) commitments (share,pub) =
    proofVerify (proofParams dleq) (shareValidProof share)
  where dleq = DLEQ
                { dleq_g1 = g
                , dleq_h1 = xi
                , dleq_g2 = pub
                , dleq_h2 = shareEncryptedVal share
                }
        xi = createXi (fromIntegral $ shareID share) commitments

-- | Verify that a decrypted share is valid, i.e.
-- the decrypted share given back by a participant is valid.
pvssVerifyDecryptedShare :: ArithKey scalar point
                         => (EncryptedShare point scalar, point, DecryptedShare point scalar)
                         -> Bool
pvssVerifyDecryptedShare (eshare,pub,share) =
    proofVerify (proofParams dleq) (decryptedValidProof share)
  where dleq = DLEQ curveGenerator pub (shareDecryptedVal share) (shareEncryptedVal eshare)

pvssPoolShares :: ArithKey scalar point
               => Threshold
               -> [DecryptedShare point scalar]
               -> Either String DhSecret
pvssPoolShares t allShares
    | length allShares < fromIntegral t = Left ("cannot interpolate: need " ++ show t ++ " shares, but got " ++ show (length shares))
    | otherwise = Right $ publicKeyToDhSecret $ foldl interpolate publicKeyIdentity (zip shares [0..])
  where -- take only the number of shares we need (t shares) to recover
        shares = take (fromIntegral t) allShares

        getShareNB :: ShareId -> Integer
        getShareNB i = decryptedShareID (shares !!! fromIntegral i)

        interpolate :: ArithKey scalar point => point -> (DecryptedShare point scalar, ShareId) -> point
        interpolate !result (share, sid) = result `publicKeyAdd` (shareDecryptedVal share `publicKeyMulFlip` value)
          where value = calc 0 (keyFromNum 1)
                calc :: ArithKey scalar point => Integer -> scalar -> scalar
                calc !j acc
                    | j == t       = acc
                    | j == sid     = calc (j+1) acc
                    | otherwise    =
                        let sj   = getShareNB j
                            si   = getShareNB sid
                            dinv = keyInverse $ (keyFromNum sj `keySubtract` keyFromNum si)
                            e    = keyFromNum sj `keyMul` dinv
                         in calc (j+1) (acc `keyMul` e)

        (!!!) s i | length s > i = s !! i
                  | otherwise    = error ("!!! " ++ show i ++ " on length " ++ show (length s))

-- | pool multiple reconstructed shares without verifying
-- that the decrypted shares are valid.
pvssRecoverNoVerify :: (DhDerivedSymmetric alg, ArithKey scalar point)
                    => Threshold
                    -> [DecryptedShare point scalar] -- ^ the decrypted shares to participate in the secret recovery. 't' shares needed.
                    -> SecretSharesLocked alg   -- ^ the encrypted secret (referenced as 'U' in the paper)
                    -> Either String ByteString -- ^ the recovered secret on success or an error
pvssRecoverNoVerify t allShares esecret =
    case pvssPoolShares t allShares of
        Left err -> Left err
        Right xx -> maybe (Left "cannot decrypt secret") Right $ pvssDecryptSecret xx esecret

-- | Try to reconstruct the secret by pooling the decrypted shares from the participants.
-- the shares are verified first, and then we call the compute the lagrange interpolation
-- in poolSharesNoVerify
--
-- TODO: filter out the proof that do not verify and see if there's enough (t)
-- to compute the recovery.
pvssRecover :: (DhDerivedSymmetric alg, ArithKey scalar point)
            => Threshold
            -> [(EncryptedShare point scalar, point, DecryptedShare point scalar)]
            -> SecretSharesLocked alg
            -> Either String ByteString
pvssRecover threshold shares esecret
    | allSharesValid = pvssRecoverNoVerify threshold allDecShares esecret
    | otherwise      = Left "shares invalid"
  where allSharesValid = and' $ map pvssVerifyDecryptedShare shares
        allDecShares   = map (\(_,_,d) -> d) shares

-- | create the Xi value from the commitments Cj
--
-- Xi is an element of the Group g
createXi :: ArithKey scalar point
         => ShareId            -- ^ index i
         -> [Commitment point] -- ^ all commitments
         -> point
createXi i (map unCommitment -> commitments) =
    let es  = [ (keyFromNum (fromIntegral i) `keyPower` j) | j <- [0..] ]
     in foldr1 publicKeyAdd $ zipWith publicKeyMulFlip commitments es

-- derive a dhsecret from gS and encrypt symmetricly the secret with it
pvssEncryptSecret :: DhDerivedSymmetric alg => DhSecret -> ByteString -> SecretSharesLocked alg
pvssEncryptSecret gS bs = doEncrypt Proxy
  where dhsecret = DhSecret $ toBytes $ sha512Hash $ toBytes gS
        doEncrypt :: DhDerivedSymmetric alg => Proxy alg -> SecretSharesLocked alg
        doEncrypt proxy = SecretSharesLocked $ dhdsEncryptSimple proxy dhsecret bs

-- derive a dhsecret from gS and decrypt symmetricly the secret with it
pvssDecryptSecret :: DhDerivedSymmetric alg => DhSecret -> SecretSharesLocked alg -> Maybe ByteString
pvssDecryptSecret gS ssl@(SecretSharesLocked bs) = withProxy ssl (\proxy -> dhdsDecryptSimple proxy dhsecret bs)
  where
        dhsecret = DhSecret $ toBytes $ sha512Hash $ toBytes gS
        withProxy :: SecretSharesLocked alg -> (Proxy alg -> a) -> a
        withProxy _ f = f Proxy

-- | one parameter to generate a NIZK proof.
--
-- for a given secret value a we want to make a proof that
-- g1 ^ a = h1  && g2 ^ a = h2
data DLEQ point = DLEQ
    { dleq_g1 :: point
    , dleq_h1 :: point
    , dleq_g2 :: point
    , dleq_h2 :: point
    } deriving (Show,Eq)

data ProofParams point = ProofParams (DLEQ point) ([point] -> ByteString)

proofParams :: ArithKey scalar point => DLEQ point -> ProofParams point
proofParams dleq = ProofParams dleq hashSHA256

-- | Non interactive Chaum & Pedersen scheme.
--
-- this is the value needed for a verifier with the same
-- input parameters 'ProofParams' to prove knowledge.
data Proof point scalar = Proof
    { proof_a1 :: !point
    , proof_a2 :: !point
    , proof_z  :: !scalar
    } deriving (Show,Eq,Generic)

instance (NFData point, NFData scalar) => NFData (Proof point scalar)

instance (ToACN point, ToACN scalar) => ToACN (Proof point scalar) where
    toACN (Proof a1 a2 z) = toACN (a1, a2, z)
instance (FromACN point, FromACN scalar) => FromACN (Proof point scalar) where
    fromACN l = case fromACN l of
                    Left err               -> Left ("Proof: " ++ err)
                    Right ((a1, a2, z),l') -> Right (Proof a1 a2 z, l')

proofGenerate :: ArithKey scalar point
              => String
              -> scalar
              -> scalar
              -> ProofParams point
              -> Proof point scalar
proofGenerate name w a pp@(ProofParams (DLEQ g1 h1 g2 h2) hashAlg)
    | internalCheck (not paramValid) = error ("internal error: proofGenerate(" ++ name ++ ") not valid parameter")
    | internalCheck (not valid)      = error ("internal error: proofGenerate(" ++ name ++ ") fail to verify")
    | otherwise                      = proof
  where
        -- those following values are expensive to evaluate
        valid      = proofVerify pp proof
        paramValid = ((g1 `publicKeyMulFlip` a) == h1) && ((g2 `publicKeyMulFlip` a) == h2)

        -- product a proof by creating 'a1=g1^w' and 'a2=g2^w', which are subsequentially hashed
        -- into 'c' and then mixed with the object of the proof 'a' to produce 'r = w - ac'
        proof  = Proof a1 a2 r
        a1     = g1 `publicKeyMulFlip` w
        a2     = g2 `publicKeyMulFlip` w
        c      = ecScalarFromBytes $ hashAlg [a1,a2]
        r      = w `keyAdd` (a `keyMul` c)

proofVerify :: ArithKey scalar point => ProofParams point -> Proof point scalar -> Bool
proofVerify (ProofParams (DLEQ g1 h1 g2 h2) hashAlg) (Proof a1 a2 r) =
    and' [r1 == v1 ,r2 == v2]
  where
        c  = ecScalarFromBytes $ hashAlg [a1,a2]
        r1 = g1 `publicKeyMulFlip` r
        r2 = g2 `publicKeyMulFlip` r
        v1 = a1 `publicKeyAdd` (h1 `publicKeyMulFlip` c)
        v2 = a2 `publicKeyAdd` (h2 `publicKeyMulFlip` c)

hashSHA256 :: Bytes point => [point] -> ByteString
hashSHA256 elements = toBytes $ sha256Hash $ mconcat $ map (toBytes) elements

{-
hashSHA512 :: [point] -> ByteString
hashSHA512 elements = PB.toBytes $ sha512Hash $ mconcat $ map (PB.toBytes) elements
-}

-- | This is a strict version of and
and' :: [Bool] -> Bool
and' l = foldl' (&&!) True l

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False

ecScalarFromBytes :: ArithKey scalar point => ByteString -> scalar
ecScalarFromBytes = keyFromNum . os2ip
  where os2ip :: ByteString -> Integer
        os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

curveGenerator :: ArithKey scalar point => point
curveGenerator = publicKeyFromSecret $ keyFromNum 1

-- | a group of coefficient starting from the
-- smallest degree.
--
newtype Polynomial a = Polynomial [a]
    deriving (Eq)

polyRandom :: AsymmetricCrypto scalar point => Int -> IO (Polynomial scalar)
polyRandom i = Polynomial <$> replicateM i keyGenerate

polyEval :: ArithKey scalar point => Polynomial scalar -> scalar -> scalar
polyEval (Polynomial a) v = foldl1 keyAdd $ map evalDeg (zip a [0 :: Integer ..])
  where evalDeg (coeff, degree) = coeff `keyMul` (v `keyPower` degree)
