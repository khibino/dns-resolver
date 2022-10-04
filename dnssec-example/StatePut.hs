{-# LANGUAGE FlexibleInstances #-}

module StatePut where

import Control.Monad.Trans.State.Strict (State)
import qualified Control.Monad.Trans.State.Strict as ST
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word8, Word16, Word32)
import Data.Map (Map)
import qualified Data.Map as M
import Data.Semigroup as Sem

import Network.DNS (Domain, Mailbox)


type SPut = State WState Builder

runSPut :: SPut -> ByteString
runSPut = LB.toStrict . BB.toLazyByteString . flip ST.evalState initialWState

data WState = WState {
    wsDomain :: Map Domain Int
  , wsPosition :: Int
}

initialWState :: WState
initialWState = WState M.empty 0

instance Sem.Semigroup SPut where
    p1 <> p2 = (Sem.<>) <$> p1 <*> p2

instance Monoid SPut where
    mempty = return mempty
    mappend = (Sem.<>)

put8 :: Word8 -> SPut
put8 = fixedSized 1 BB.word8

put16 :: Word16 -> SPut
put16 = fixedSized 2 BB.word16BE

put32 :: Word32 -> SPut
put32 = fixedSized 4 BB.word32BE

putInt8 :: Int -> SPut
putInt8 = fixedSized 1 (BB.int8 . fromIntegral)

putInt16 :: Int -> SPut
putInt16 = fixedSized 2 (BB.int16BE . fromIntegral)

putInt32 :: Int -> SPut
putInt32 = fixedSized 4 (BB.int32BE . fromIntegral)

putByteString :: ByteString -> SPut
putByteString = writeSized BS.length BB.byteString

putReplicate :: Int -> Word8 -> SPut
putReplicate n w =
    fixedSized n BB.lazyByteString $ LB.replicate (fromIntegral n) w

addPositionW :: Int -> State WState ()
addPositionW n = do
    (WState m cur) <- ST.get
    ST.put $ WState m (cur+n)

fixedSized :: Int -> (a -> Builder) -> a -> SPut
fixedSized n f a = do addPositionW n
                      return (f a)

writeSized :: (a -> Int) -> (a -> Builder) -> a -> SPut
writeSized n f a = do addPositionW (n a)
                      return (f a)

wsPop :: Domain -> State WState (Maybe Int)
wsPop dom = do
    doms <- ST.gets wsDomain
    return $ M.lookup dom doms

wsPush :: Domain -> Int -> State WState ()
wsPush dom pos = do
    (WState m cur) <- ST.get
    ST.put $ WState (M.insert dom pos m) cur

---

-- In the case of the TXT record, we need to put the string length
-- fixme : What happens with the length > 256 ?
putByteStringWithLength :: BS.ByteString -> SPut
putByteStringWithLength bs = putInt8 (fromIntegral $ BS.length bs) -- put the length of the given string
                          <> putByteString bs

rootDomain :: Domain
rootDomain = B8.pack "."

putDomainNC :: Domain -> SPut
putDomainNC = putDomainNC' '.'

putMailboxNC :: Mailbox -> SPut
putMailboxNC = putDomainNC' '@'

putDomainNC' :: Char -> ByteString -> SPut
putDomainNC' sep1 dom
  | BS.null dom || dom == rootDomain = put8 0
  | otherwise = mconcat $ putPartialDomain hd : map putPartialDomain (B8.split '.' tl)
  where
    (hd, tl) =
      case splitLabel1 sep1 dom of
        (xs, ys)
          | sep1 /= '.' && BS.null ys  ->  splitLabel1 '.' dom
          | otherwise                  ->  (xs, ys)
    splitLabel1 sep bs  {- naive impl parseLabel for dnssec-example -}
      | BS.null ys  =  (xs, ys)
      | otherwise   =  (xs, BS.drop 1 ys)
      where (xs, ys) = B8.break (== sep) bs
    -- c2w = fromIntegral . fromEnum

putPartialDomain :: ByteString -> SPut
putPartialDomain = putByteStringWithLength
