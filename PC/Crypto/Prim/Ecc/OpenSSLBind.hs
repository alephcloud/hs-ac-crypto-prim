-- ------------------------------------------------------ --
-- Copyright © 2013 AlephCloud Systems, Inc.
-- ------------------------------------------------------ --

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls #-}
module PC.Crypto.Prim.Ecc.OpenSSLBind
    ( Point
    , Group
    , Key
    , PointConversionForm(..)
    , Nid
    -- * ASN1 nid
    , txt2Nid
    -- * group
    , groupFromCurveName
    , groupGFp
    , groupGF2m
    , groupGetDegree
    , groupGetOrder
    , groupGetCoFactor
    , groupGetGenerator
    , groupGetCurveGFp
    , groupGetCurveGF2m
    -- * point arithmetic
    , pointAdd
    , pointDbl
    , pointMul
    , pointMulWithGenerator
    , pointGeneratorMul
    , pointInvert
    , pointInfinity
    , pointIsAtInfinity
    , pointIsOnCurve
    , pointEq
    -- * point serialization
    , pointToOct
    , octToPoint
    , pointFromJProjectiveGFp
    , pointToJProjectiveGFp
    , pointFromAffineGFp
    , pointToAffineGFp
    , pointFromAffineGF2m
    , pointToAffineGF2m
    -- * key 
    , keyGenerateNew
    , keyFromPair
    , keyToPair
    ) where

-- #include "openssl/ec.h"
-- #include "openssl/bn.h"

import Control.Monad (void)
import Control.Applicative
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String (withCString)
import Data.ByteString (ByteString)
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import System.IO.Unsafe (unsafePerformIO)

-- | An ellitic curve group
newtype Group = Group (ForeignPtr EC_GROUP)

-- | An elliptic curve point
newtype Point = Point (ForeignPtr EC_POINT)

-- | An elliptic curve key
newtype Key = Key (ForeignPtr EC_KEY)

-- | openssl ASN1 NID
type Nid = Int

--------------------------------------
-- openssl types

data EC_GROUP
data EC_POINT
data EC_KEY
data BN_CTX
data BIGNUM

type PointConversionFormT = CInt

--------------------------------------
-- | different way to marshall a point
data PointConversionForm =
      PointConversion_Compressed
    | PointConversion_Uncompressed
    | PointConversion_Hybrid
    deriving (Show,Eq)

pointConversionToC :: PointConversionForm -> PointConversionFormT
pointConversionToC PointConversion_Compressed   = 2
pointConversionToC PointConversion_Uncompressed = 4
pointConversionToC PointConversion_Hybrid       = 6

doIO :: IO a -> a
doIO = unsafePerformIO

-------------------------------
-- ASN1 nids

foreign import ccall unsafe "OBJ_txt2nid"
    _obj_txt2nid :: Ptr CChar -> IO CInt

txt2Nid :: String -> Maybe Nid
txt2Nid s = doIO $
    (mnid <$> withCString s (_obj_txt2nid))
  where mnid 0 = Nothing
        mnid i = Just (fromIntegral i)

-------------------------------
-- BN related functions
foreign import ccall unsafe "&BN_CTX_free"
    _bn_ctx_free :: FunPtr (Ptr BN_CTX -> IO ())

foreign import ccall unsafe "BN_CTX_new"
    _bn_ctx_new :: IO (Ptr BN_CTX)

foreign import ccall unsafe "BN_new"
    _bn_new :: IO (Ptr BIGNUM)

foreign import ccall unsafe "&BN_free"
    _bn_free :: FunPtr (Ptr BIGNUM -> IO ())

foreign import ccall unsafe "BN_num_bits"
    _bn_num_bits :: Ptr BIGNUM -> IO CInt

{- the following is a C macro, use num_bits instead
foreign import ccall unsafe "BN_num_bytes"
    _bn_num_bytes :: Ptr BIGNUM -> IO CInt
-}

_bn_num_bytes :: Ptr BIGNUM -> IO CInt
_bn_num_bytes ptr = do
    bits <- _bn_num_bits ptr
    return $ ((bits + 7) `div` 8)

foreign import ccall unsafe "BN_bn2bin"
    _bn_2bin :: Ptr BIGNUM -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "BN_bin2bn"
    _bn_bin2 :: Ptr CUChar -> CInt -> Ptr BIGNUM -> IO (Ptr BIGNUM)

withIntegerAsBN :: Integer -> (Ptr BIGNUM -> IO a) -> IO a
withIntegerAsBN i f = do
    bn <- withForeignPtr fptr $ \bsPtr ->
            _bn_bin2 (castPtr (bsPtr `plusPtr` o)) (fromIntegral len) nullPtr
    foreignBn <- newForeignPtr _bn_free bn
    withForeignPtr foreignBn f
  where (fptr, o, len) = B.toForeignPtr bs
        bs = B.reverse $ B.unfoldr fdivMod256 i
        fdivMod256 0 = Nothing
        fdivMod256 n = Just (fromIntegral a,b) where (b,a) = divMod256 n
        divMod256 :: Integer -> (Integer, Integer)
        divMod256 n = (n `shiftR` 8, n .&. 0xff)

bnToInt :: Ptr BIGNUM -> IO Integer
bnToInt bn = do
    bytes <- _bn_num_bytes bn
    bs    <- B.create (fromIntegral bytes) $ \bufPtr ->
                check $ _bn_2bin bn (castPtr bufPtr)
    return $ os2ip bs
  where os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

-------------------------------
-- EC_GROUP related functions

foreign import ccall unsafe "&EC_GROUP_free"
    _group_free :: FunPtr (Ptr EC_GROUP -> IO ())

foreign import ccall unsafe "EC_GROUP_new_by_curve_name"
    _group_new_by_curve_name :: CInt -> IO (Ptr EC_GROUP)

foreign import ccall unsafe "EC_GROUP_new_curve_GF2m"
    _group_new_curve_GF2m :: Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO (Ptr EC_GROUP)

foreign import ccall unsafe "EC_GROUP_new_curve_GFp"
    _group_new_curve_GFp :: Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO (Ptr EC_GROUP)

foreign import ccall unsafe "EC_GROUP_get_order"
    _group_get_order :: Ptr EC_GROUP -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_GROUP_get_cofactor"
    _group_get_cofactor :: Ptr EC_GROUP -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_GROUP_get_degree"
    _group_get_degree :: Ptr EC_GROUP -> IO CInt

foreign import ccall unsafe "EC_GROUP_get_curve_GFp"
    _group_get_curve_gfp :: Ptr EC_GROUP -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_GROUP_get_curve_GF2m"
    _group_get_curve_gf2m :: Ptr EC_GROUP -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_GROUP_get0_generator"
    _group_get0_generator :: Ptr EC_GROUP -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_GROUP_get_curve_name"
    _group_get_curve_name :: Ptr EC_GROUP -> IO CInt

foreign import ccall unsafe "EC_GROUP_set_generator"
    _group_set_generator :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> IO CInt

-------------------------------
-- EC_POINT related functions

foreign import ccall unsafe "&EC_POINT_free"
    _point_free_funptr :: FunPtr (Ptr EC_POINT -> IO ())

foreign import ccall unsafe "EC_POINT_free"
    _point_free :: Ptr EC_POINT -> IO ()

foreign import ccall unsafe "&EC_POINT_clear_free"
    _point_clear_free :: FunPtr (Ptr EC_POINT -> IO ())

foreign import ccall unsafe "EC_POINT_new"
    _point_new :: Ptr EC_GROUP -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_POINT_dup"
    _point_dup :: Ptr EC_POINT -> Ptr EC_GROUP -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_POINT_copy"
    _point_copy :: Ptr EC_POINT -> Ptr EC_POINT -> IO CInt

foreign import ccall unsafe "EC_POINT_add"
    _point_add :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr EC_POINT -> Ptr EC_POINT -> Ptr BN_CTX -> IO CInt
foreign import ccall unsafe "EC_POINT_mul"
    _point_mul :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt
foreign import ccall unsafe "EC_POINT_dbl"
    _point_dbl :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr EC_POINT -> Ptr BN_CTX -> IO CInt
foreign import ccall unsafe "EC_POINT_invert"
    _point_invert :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BN_CTX -> IO CInt

-- 1 is true, 0 false
foreign import ccall unsafe "EC_POINT_is_at_infinity"
    _point_is_at_infinity :: Ptr EC_GROUP -> Ptr EC_POINT -> IO CInt
-- 1 is true, 0 false
foreign import ccall unsafe "EC_POINT_is_on_curve"
    _point_is_on_curve :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BN_CTX -> IO CInt

-- 1 not equal, 0 equal, -1 error
foreign import ccall unsafe "EC_POINT_cmp"
    _point_cmp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr EC_POINT -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_point2oct"
    _point_2oct :: Ptr EC_GROUP -> Ptr EC_POINT -> PointConversionFormT -> Ptr CUChar -> CSize -> Ptr BN_CTX -> IO CSize

foreign import ccall unsafe "EC_POINT_oct2point"
    _point_oct2 :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr CUChar -> CSize -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_point2bn"
    _point_2bn :: Ptr EC_GROUP -> Ptr EC_POINT -> PointConversionFormT -> Ptr BIGNUM -> Ptr BN_CTX -> IO (Ptr BIGNUM)

foreign import ccall unsafe "EC_POINT_bn2point"
    _point_bn2 :: Ptr EC_GROUP -> Ptr BIGNUM -> Ptr EC_POINT -> Ptr BN_CTX -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_POINT_point2hex"
    _point_2hex :: Ptr EC_GROUP -> Ptr EC_POINT -> PointConversionFormT -> Ptr BN_CTX -> IO (Ptr CChar)

foreign import ccall unsafe "EC_POINT_hex2point"
    _point_hex2 :: Ptr EC_GROUP -> Ptr CChar -> Ptr EC_POINT -> Ptr BN_CTX -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_POINT_set_to_infinity"
    _point_set_to_infinity :: Ptr EC_GROUP -> Ptr EC_POINT -> IO CInt

foreign import ccall unsafe "EC_POINT_set_Jprojective_coordinates_GFp"
    _point_set_Jprojective_coordinates_GFp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_get_Jprojective_coordinates_GFp"
    _point_get_Jprojective_coordinates_GFp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_set_affine_coordinates_GFp"
    _point_set_affine_coordinates_GFp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_get_affine_coordinates_GFp"
    _point_get_affine_coordinates_GFp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_set_affine_coordinates_GF2m"
    _point_set_affine_coordinates_GF2m :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_get_affine_coordinates_GF2m"
    _point_get_affine_coordinates_GF2m :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> Ptr BIGNUM -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_set_compressed_coordinates_GFp"
    _point_set_compressed_coordinates_GFp :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> CInt -> Ptr BN_CTX -> IO CInt

foreign import ccall unsafe "EC_POINT_set_compressed_coordinates_GF2m"
    _point_set_compressed_coordinates_GF2m :: Ptr EC_GROUP -> Ptr EC_POINT -> Ptr BIGNUM -> CInt -> Ptr BN_CTX -> IO CInt

-------------------------------
-- EC_KEY related functions

foreign import ccall unsafe "EC_KEY_new"
    _key_new :: IO (Ptr EC_KEY)

foreign import ccall unsafe "&EC_KEY_free"
    _key_free :: FunPtr (Ptr EC_KEY -> IO ())

foreign import ccall unsafe "EC_KEY_get0_group"
    _key_get0_group :: Ptr EC_KEY -> IO (Ptr EC_GROUP)

foreign import ccall unsafe "EC_KEY_set_group"
    _key_set_group :: Ptr EC_KEY -> Ptr EC_GROUP -> IO CInt

foreign import ccall unsafe "EC_KEY_generate_key"
    _key_generate_key :: Ptr EC_KEY -> IO CInt

foreign import ccall unsafe "EC_KEY_get0_private_key"
    _key_get0_private_key :: Ptr EC_KEY -> IO (Ptr BIGNUM)

foreign import ccall unsafe "EC_KEY_get0_public_key"
    _key_get0_public_key :: Ptr EC_KEY -> IO (Ptr EC_POINT)

foreign import ccall unsafe "EC_KEY_set_private_key"
    _key_set_private_key :: Ptr EC_KEY -> Ptr BIGNUM -> IO CInt

foreign import ccall unsafe "EC_KEY_set_public_key"
    _key_set_public_key :: Ptr EC_KEY -> Ptr EC_POINT -> IO CInt

check :: IO CInt -> IO ()
check f = do
    r <- f
    if r == 0
        then error ("check failed returned: " ++ show r)
        else return ()

withBnCtxNew :: (Ptr BN_CTX -> IO a) -> IO a
withBnCtxNew f = do
    -- UGLY, can do something more clever than this ..
    fptr <- _bn_ctx_new >>= newForeignPtr _bn_ctx_free
    withForeignPtr fptr f

withBnNew :: (Ptr BIGNUM -> IO a) -> IO a
withBnNew f = do
    fptr <- _bn_new >>= newForeignPtr _bn_free
    withForeignPtr fptr f

withPointNew :: Ptr EC_GROUP -> (Ptr EC_POINT -> IO ()) -> IO Point
withPointNew grp f = do
    ptr <- _point_new grp
    f ptr
    Point <$> newForeignPtr _point_free_funptr ptr

withPointDup :: Ptr EC_GROUP -> Ptr EC_POINT -> (Ptr EC_POINT -> IO ()) -> IO Point
withPointDup grp p f = do
    ptr <- _point_dup p grp
    f ptr
    Point <$> newForeignPtr _point_free_funptr ptr

-- | try to get a curve from a nid
groupFromCurveName :: Nid -> (Maybe Group)
groupFromCurveName i = doIO $ do
    g <- _group_new_by_curve_name (fromIntegral i)
    if g == nullPtr
        then return Nothing
        else Just . Group <$> newForeignPtr _group_free g
{-# NOINLINE groupFromCurveName #-}

-- | Create a new GFp group with explicit (p,a,b,(x,y),order,h)
groupGFp :: Integer -- ^ p
         -> Integer -- ^ a
         -> Integer -- ^ b
         -> (Integer,Integer) -- ^ generator
         -> Integer -- ^ order
         -> Integer -- ^ cofactor
         -> Group
groupGFp p a b (genX, genY) order cofactor = doIO $
    withIntegerAsBN p        $ \bnp        ->
    withIntegerAsBN a        $ \bna        ->
    withIntegerAsBN b        $ \bnb        ->
    withIntegerAsBN genX     $ \bnGX       ->
    withIntegerAsBN genY     $ \bnGY       ->
    withIntegerAsBN order    $ \bnOrder    ->
    withIntegerAsBN cofactor $ \bnCofactor ->
    withBnCtxNew             $ \bnCtx      -> do
        group <- _group_new_curve_GFp bnp bna bnb bnCtx
        point <- _point_new group
        check $ _point_set_affine_coordinates_GFp group point bnGX bnGY bnCtx
        check $ _group_set_generator group point bnOrder bnCofactor
        _point_free point
        Group <$> newForeignPtr _group_free group
{-# NOINLINE groupGFp #-}

-- | Create a new GF2m group with explicit (p,a,b,(x,y),order,h)
groupGF2m :: Integer -- ^ p
         -> Integer -- ^ a
         -> Integer -- ^ b
         -> (Integer,Integer) -- ^ generator
         -> Integer -- ^ order
         -> Integer -- ^ cofactor
         -> Group
groupGF2m p a b (genX, genY) order cofactor = doIO $
    withIntegerAsBN p        $ \bnp        ->
    withIntegerAsBN a        $ \bna        ->
    withIntegerAsBN b        $ \bnb        ->
    withIntegerAsBN genX     $ \bnGX       ->
    withIntegerAsBN genY     $ \bnGY       ->
    withIntegerAsBN order    $ \bnOrder    ->
    withIntegerAsBN cofactor $ \bnCofactor ->
    withBnCtxNew             $ \bnCtx      -> do
        group <- _group_new_curve_GF2m bnp bna bnb bnCtx
        point <- _point_new group
        check $ _point_set_affine_coordinates_GF2m group point bnGX bnGY bnCtx
        check $ _group_set_generator group point bnOrder bnCofactor
        _point_free point
        Group <$> newForeignPtr _group_free group
{-# NOINLINE groupGF2m #-}

-- | get the group degree (number of bytes)
groupGetDegree :: Group -> Int
groupGetDegree (Group g) = doIO $
    withForeignPtr g  $ \gptr ->
        fromIntegral <$> _group_get_degree gptr
{-# NOINLINE groupGetDegree #-}

-- | get the order of the subgroup generated by the generator
groupGetOrder :: Group -> Integer
groupGetOrder (Group g) = doIO $
    withForeignPtr g  $ \gptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \bn    -> do
        check $ _group_get_order gptr bn bnCtx
        bnToInt bn
{-# NOINLINE groupGetOrder #-}

--- | get the cofactor of the curve.
--
-- usually a small number h that:
-- h = #E(Fp) / n
groupGetCoFactor :: Group -> Integer
groupGetCoFactor (Group g) = doIO $
    withForeignPtr g  $ \gptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \bn    -> do
        check $ _group_get_cofactor gptr bn bnCtx
        bnToInt bn
{-# NOINLINE groupGetCoFactor #-}

-- | Get the group generator
groupGetGenerator :: Group -> Point
groupGetGenerator (Group g) = doIO $
    withForeignPtr g  $ \gptr ->
    withPointNew gptr $ \r    -> do
        p <- _group_get0_generator gptr
        check $ _point_copy r p
{-# NOINLINE groupGetGenerator #-}

-- | get curve's (prime,a,b)
groupGetCurveGFp :: Group -> (Integer, Integer, Integer)
groupGetCurveGFp (Group g) = doIO $
    withForeignPtr g  $ \gptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \pPtr  ->
    withBnNew         $ \aPtr  ->
    withBnNew         $ \bPtr  -> do
        check $ _group_get_curve_gfp gptr pPtr aPtr bPtr bnCtx
        (,,) <$> bnToInt pPtr <*> bnToInt aPtr <*> bnToInt bPtr
{-# NOINLINE groupGetCurveGFp #-}

-- | get curve's (polynomial,a,b)
groupGetCurveGF2m :: Group -> (Integer, Integer, Integer)
groupGetCurveGF2m (Group g) = doIO $
    withForeignPtr g  $ \gptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \pPtr  ->
    withBnNew         $ \aPtr  ->
    withBnNew         $ \bPtr  -> do
        check $ _group_get_curve_gf2m gptr pPtr aPtr bPtr bnCtx
        (,,) <$> bnToInt pPtr <*> bnToInt aPtr <*> bnToInt bPtr
{-# NOINLINE groupGetCurveGF2m #-}

{-
pointNew :: Group -> IO Point
pointNew (Group fptr) = withForeignPtr fptr $ \gptr ->
    withPointNew gptr (\_ -> return ())
-}

-- | add 2 points together, r = p1 + p2
pointAdd :: Group -> Point -> Point -> Point
pointAdd (Group g) (Point p1) (Point p2) = doIO $
    withForeignPtr g  $ \gptr  ->
    withForeignPtr p1 $ \p1ptr ->
    withForeignPtr p2 $ \p2ptr ->
    withBnCtxNew      $ \bnCtx ->
    withPointNew gptr $ \r -> check $ _point_add gptr r p1ptr p2ptr bnCtx
{-# NOINLINE pointAdd #-}

-- | compute the doubling of the point p, r = p^2
pointDbl :: Group -> Point -> Point
pointDbl (Group g) (Point p) = doIO $
    withForeignPtr g  $ \gptr ->
    withForeignPtr p  $ \pptr ->
    withBnCtxNew      $ \bnCtx ->
    withPointNew gptr $ \r -> check $ _point_dbl gptr r pptr bnCtx
{-# NOINLINE pointDbl #-}

-- | compute q * m
pointMul :: Group
         -> Point   -- ^ q
         -> Integer -- ^ m
         -> Point
pointMul (Group g) (Point q) m = doIO $
    withForeignPtr g  $ \gptr ->
    withForeignPtr q  $ \qptr ->
    withBnCtxNew      $ \bnCtx ->
    withIntegerAsBN m $ \bnM   ->
    withPointNew gptr $ \r -> check $ _point_mul gptr r nullPtr qptr bnM bnCtx
{-# NOINLINE pointMul #-}

-- | compute generator * n + q * m
pointMulWithGenerator :: Group
                      -> Integer -- ^ n
                      -> Point   -- ^ q
                      -> Integer -- ^ m
                      -> Point
pointMulWithGenerator (Group g) n (Point q) m = doIO $
    withForeignPtr g  $ \gptr ->
    withForeignPtr q  $ \qptr ->
    withBnCtxNew      $ \bnCtx ->
    withIntegerAsBN n $ \bnN   ->
    withIntegerAsBN m $ \bnM   ->
    withPointNew gptr $ \r -> check $ _point_mul gptr r bnN qptr bnM bnCtx
{-# NOINLINE pointMulWithGenerator #-}

-- | compute generator * n
pointGeneratorMul :: Group -> Integer -> Point
pointGeneratorMul (Group g) n = doIO $
    withForeignPtr g  $ \gptr  ->
    withBnCtxNew      $ \bnCtx ->
    withIntegerAsBN n $ \bnN   ->
    withPointNew gptr $ \r     -> check $ _point_mul gptr r bnN nullPtr nullPtr bnCtx
{-# NOINLINE pointGeneratorMul #-}

-- | compute the inverse on the curve on the point p, r = p^(-1)
pointInvert :: Group -> Point -> Point
pointInvert (Group g) (Point p) = doIO $
    withForeignPtr g       $ \gptr ->
    withForeignPtr p       $ \pptr ->
    withBnCtxNew           $ \bnCtx ->
    withPointDup gptr pptr $ \dupptr  ->
        check $ _point_invert gptr dupptr bnCtx
{-# NOINLINE pointInvert #-}

pointInfinity :: Group -> Point
pointInfinity (Group g) = doIO $
    withForeignPtr g  $ \gptr  ->
    withPointNew gptr $ \r     ->
        check $ _point_set_to_infinity gptr r
{-# NOINLINE pointInfinity #-}

-- | get if the point is at infinity
pointIsAtInfinity :: Group -> Point -> Bool
pointIsAtInfinity (Group g) (Point p) = doIO $
    withForeignPtr g $ \gptr ->
    withForeignPtr p $ \pptr ->
    ((==) 1 <$> _point_is_at_infinity gptr pptr)
{-# NOINLINE pointIsAtInfinity #-}

-- | get if the point is on the curve
pointIsOnCurve :: Group -> Point -> Bool
pointIsOnCurve (Group g) (Point p) = doIO $
    withForeignPtr g $ \gptr ->
    withForeignPtr p $ \pptr ->
    withBnCtxNew     $ \bnCtx ->
    ((==) 1 <$> _point_is_on_curve gptr pptr bnCtx)
{-# NOINLINE pointIsOnCurve #-}

pointToOct :: Group -> Point -> PointConversionForm -> ByteString
pointToOct (Group g) (Point p) pconv = doIO $
    withForeignPtr g $ \gptr  ->
    withForeignPtr p $ \pptr  ->
    withBnCtxNew     $ \bnCtx -> do
        lenRequired <- _point_2oct gptr pptr form nullPtr 0 bnCtx
        B.create (fromIntegral lenRequired) $ \buf -> do
            void $ _point_2oct gptr pptr form (castPtr buf) lenRequired bnCtx
  where form = pointConversionToC pconv
{-# NOINLINE pointToOct #-}

octToPoint :: Group -> ByteString -> Point
octToPoint (Group g) bs = doIO $
    withForeignPtr g    $ \gptr ->
    withForeignPtr fptr $ \bsPtr ->
    withBnCtxNew        $ \bnCtx ->
    withPointNew gptr   $ \r ->
        let buf = castPtr (bsPtr `plusPtr` o)
         in check $ _point_oct2 gptr r buf (fromIntegral len) bnCtx
  where (fptr, o, len) = B.toForeignPtr bs
{-# NOINLINE octToPoint #-}

pointFromJProjectiveGFp :: Group -> (Integer,Integer,Integer) -> Point
pointFromJProjectiveGFp (Group g) (x,y,z) = doIO $
    withForeignPtr g    $ \gptr  ->
    withBnCtxNew        $ \bnCtx ->
    withIntegerAsBN x   $ \bnX   ->
    withIntegerAsBN y   $ \bnY   ->
    withIntegerAsBN z   $ \bnZ   ->
    withPointNew gptr   $ \r ->
        check $ _point_set_Jprojective_coordinates_GFp gptr r bnX bnY bnZ bnCtx
{-# NOINLINE pointFromJProjectiveGFp #-}

pointToJProjectiveGFp :: Group -> Point -> (Integer,Integer,Integer)
pointToJProjectiveGFp (Group g) (Point p) = doIO $
    withForeignPtr g  $ \gptr  ->
    withForeignPtr p  $ \pptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \bnX   ->
    withBnNew         $ \bnY   ->
    withBnNew         $ \bnZ   -> do
        check $ _point_get_Jprojective_coordinates_GFp gptr pptr bnX bnY bnZ bnCtx
        (,,) <$> bnToInt bnX <*> bnToInt bnY <*> bnToInt bnZ
{-# NOINLINE pointToJProjectiveGFp #-}

pointFromAffineGFp :: Group -> (Integer, Integer) -> Point
pointFromAffineGFp (Group g) (x,y) = doIO $
    withForeignPtr g    $ \gptr  ->
    withBnCtxNew        $ \bnCtx ->
    withIntegerAsBN x   $ \bnX   ->
    withIntegerAsBN y   $ \bnY   ->
    withPointNew gptr   $ \r ->
        check $ _point_set_affine_coordinates_GFp gptr r bnX bnY bnCtx
{-# NOINLINE pointFromAffineGFp #-}

pointToAffineGFp :: Group -> Point -> (Integer, Integer)
pointToAffineGFp (Group g) (Point p) = doIO $
    withForeignPtr g  $ \gptr  ->
    withForeignPtr p  $ \pptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \bnX   ->
    withBnNew         $ \bnY   -> do
        check $ _point_get_affine_coordinates_GFp gptr pptr bnX bnY bnCtx
        (,) <$> bnToInt bnX <*> bnToInt bnY
{-# NOINLINE pointToAffineGFp #-}

pointFromAffineGF2m :: Group -> (Integer, Integer) -> Point
pointFromAffineGF2m (Group g) (x,y) = doIO $
    withForeignPtr g    $ \gptr  ->
    withBnCtxNew        $ \bnCtx ->
    withIntegerAsBN x   $ \bnX   ->
    withIntegerAsBN y   $ \bnY   ->
    withPointNew gptr   $ \r ->
        check $ _point_set_affine_coordinates_GF2m gptr r bnX bnY bnCtx
{-# NOINLINE pointFromAffineGF2m #-}

pointToAffineGF2m :: Group -> Point -> (Integer, Integer)
pointToAffineGF2m (Group g) (Point p) = doIO $
    withForeignPtr g  $ \gptr  ->
    withForeignPtr p  $ \pptr  ->
    withBnCtxNew      $ \bnCtx ->
    withBnNew         $ \bnX   ->
    withBnNew         $ \bnY   -> do
        check $ _point_get_affine_coordinates_GF2m gptr pptr bnX bnY bnCtx
        (,) <$> bnToInt bnX <*> bnToInt bnY
{-# NOINLINE pointToAffineGF2m #-}

-- | return if a point eq another point
pointEq :: Group -> Point -> Point -> Bool
pointEq (Group g) (Point p1) (Point p2) = doIO $
    withForeignPtr g  $ \gptr ->
    withForeignPtr p1 $ \ptr1 ->
    withForeignPtr p2 $ \ptr2 ->
    withBnCtxNew      $ \bnCtx ->
        (== 0) <$> _point_cmp gptr ptr1 ptr2 bnCtx
{-# NOINLINE pointEq #-}

-- | generate a new key in a specific group
keyGenerateNew :: Group -> IO Key
keyGenerateNew (Group g) =
    withForeignPtr g  $ \gptr -> do
        key <- _key_new
        check $ _key_set_group key gptr
        check $ _key_generate_key key
        Key <$> newForeignPtr _key_free key

-- | create a key from a group and a private integer and public point keypair
keyFromPair :: Group -> (Integer, Point) -> Key
keyFromPair (Group g) (i, (Point p)) = doIO $
    withForeignPtr g  $ \gptr ->
    withForeignPtr p  $ \pptr ->
    withIntegerAsBN i $ \bnI  -> do
        key <- _key_new
        check $ _key_set_group key gptr
        check $ _key_set_private_key key bnI
        check $ _key_set_public_key key pptr
        Key <$> newForeignPtr _key_free key

-- | return the private integer and public point of a key
keyToPair :: Key -> (Integer, Point)
keyToPair (Key k) = doIO $
    withForeignPtr k $ \kptr -> do
        gptr  <- _key_get0_group kptr
        point <- withPointNew gptr $ \r -> do
                    p <- _key_get0_public_key kptr
                    check $ _point_copy r p
        priv <- _key_get0_private_key kptr >>= bnToInt
        return (priv, point)
