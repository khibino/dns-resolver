module DNSC.Queue (
  ReadQueue (..),
  WriteQueue (..),
  QueueSize (..),
  ReadQueueSTM (..),
  WriteQueueSTM (..),
  TQ, newQueue,
  ChanQ, newQueueChan,
  Q1, newQueue1,
  GetAny, makeGetAny,
  PutAny, makePutAny,
  ) where

import Control.Monad (guard, msum, when, (<=<))
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.STM
  (TVar, newTVar, readTVar, modifyTVar', writeTVar,
   TMVar, newEmptyTMVar, takeTMVar, putTMVar, isEmptyTMVar,
   TQueue, newTQueue, readTQueue, writeTQueue,
   atomically, STM)


class ReadQueue q where
  readQueue :: q a -> IO a

class WriteQueue q where
  writeQueue :: q a -> a -> IO ()

class QueueSize q where
  sizeMaxBound :: q a -> Int
  readSizes :: q a -> IO (Int, Int)

class ReadQueueSTM q where
  waitReadQueueSTM :: q a -> STM ()
  readQueueSTM :: q a -> STM a

class WriteQueueSTM q where
  waitWriteQueueSTM :: q a -> STM ()
  writeQueueSTM :: q a -> a -> STM ()

---

makeReadSizesAny :: QueueSize q => [q a] -> IO (Int, Int)
makeReadSizesAny qs = do
  (ss, xs) <- unzip <$> mapM readSizes qs
  return (sum ss, sum xs)

data GetAny a =
  GetAny
  { getAnyCycle :: TVar [(STM (), STM a)]
  , getAnyQueues :: Int
  , getAnyMaxBound :: Int
  , getAnyReadSizes :: IO (Int, Int)
  }

makeGetAny :: (ReadQueueSTM q, QueueSize q) => [q a] -> IO (GetAny a)
makeGetAny qs = atomically $ do
  GetAny
  <$> newTVar c
  <*> pure (length qs)
  <*> pure (sum $ map sizeMaxBound qs)
  <*> pure (makeReadSizesAny qs)
  where
    c = cycle [ (waitReadQueueSTM q, readQueueSTM q) | q <- qs]

readableAnySTM :: GetAny a -> STM ()
readableAnySTM getA = do
  gs <- readTVar $ getAnyCycle getA
  msum [ wait | (wait, _) <- take (getAnyQueues getA) gs ]

getAnySTM :: GetAny a -> STM a
getAnySTM getA = do
  gs <- readTVar $ getAnyCycle getA
  a  <- msum [ get | (_, get) <- take (getAnyQueues getA) gs ]
  let z = tail gs
  z `seq` writeTVar (getAnyCycle getA) z
  return a

instance QueueSize GetAny where
  sizeMaxBound = getAnyMaxBound
  readSizes = getAnyReadSizes

instance ReadQueueSTM GetAny where
  waitReadQueueSTM = readableAnySTM
  readQueueSTM = getAnySTM

instance ReadQueue GetAny where
  readQueue = atomically . getAnySTM

data PutAny a =
  PutAny
  { putAnyCycle :: TVar [(STM (), a -> STM ())]
  , putAnyQueues ::Int
  , putAnyMaxBound :: Int
  , putAnyReadSizes :: IO (Int, Int)
  }

makePutAny :: (WriteQueueSTM q, QueueSize q) => [q a] -> IO (PutAny a)
makePutAny qs = atomically $ do
  PutAny
  <$> newTVar c
  <*> pure (length qs)
  <*> pure (sum $ map sizeMaxBound qs)
  <*> pure (makeReadSizesAny qs)
  where
    c = cycle [ (waitWriteQueueSTM q, writeQueueSTM q) | q <- qs ]

writableAnySTM :: PutAny a -> STM ()
writableAnySTM putA = do
  ps <- readTVar $ putAnyCycle putA
  msum [ wait | (wait, _) <- take (putAnyQueues putA) ps ]

putAnySTM :: PutAny a -> a -> STM ()
putAnySTM putA a = do
  ps <- readTVar $ putAnyCycle putA
  msum [ put a | (_, put) <- take (putAnyQueues putA) ps ]
  let z = tail ps
  z `seq` writeTVar (putAnyCycle putA) z

instance QueueSize PutAny where
  sizeMaxBound = putAnyMaxBound
  readSizes = putAnyReadSizes

instance WriteQueueSTM PutAny where
  waitWriteQueueSTM = writableAnySTM
  writeQueueSTM = putAnySTM

instance WriteQueue PutAny where
  writeQueue putA = atomically . putAnySTM putA

---

data TQ a =
  TQ
  { tqContent :: TQueue a
  , tqSizeRef :: TVar Int
  , tqLastMaxSizeRef :: TVar Int
  , tqSizeMaxBound :: Int
  }

newQueue :: Int -> IO (TQ a)
newQueue = atomically . newTQ

newTQ :: Int -> STM (TQ a)
newTQ xsz = TQ <$> newTQueue <*> newTVar 0 <*> newTVar 0 <*> pure xsz

readableTQ :: TQ a -> STM ()
readableTQ q = do
  sz <- readTVar $ tqSizeRef q
  guard $ sz > 0

readTQ :: TQ a -> STM a
readTQ q = do
  x <- readTQueue $ tqContent q
  let szRef = tqSizeRef q
  sz <- readTVar szRef
  updateLastMax sz
  let nsz = pred sz
  nsz `seq` writeTVar szRef nsz
  return x
  where
    updateLastMax sz = do
      let lastMaxRef = tqLastMaxSizeRef q
      mx <- readTVar lastMaxRef
      when (sz > mx) $ writeTVar lastMaxRef sz

writeableTQ :: TQ a -> STM ()
writeableTQ q = do
  sz <- readTVar $ tqSizeRef q
  guard $ sz < tqSizeMaxBound q

writeTQ :: TQ a -> a -> STM ()
writeTQ q x = do
  let szRef = tqSizeRef q
  sz <- readTVar szRef
  guard $ sz < tqSizeMaxBound q
  writeTQueue (tqContent q) x
  modifyTVar' szRef succ

readSizesTQ :: TQ a -> STM (Int, Int)
readSizesTQ q = do
  sz <- readTVar $ tqSizeRef q
  mx <- max sz <$> readTVar (tqLastMaxSizeRef q)
  return (sz, mx)

instance ReadQueue TQ where
  readQueue = atomically . readTQ

instance WriteQueue TQ where
  writeQueue q = atomically . writeTQ q

instance QueueSize TQ where
  sizeMaxBound = tqSizeMaxBound
  readSizes = atomically . readSizesTQ

instance ReadQueueSTM TQ where
  waitReadQueueSTM = readableTQ
  readQueueSTM = readTQ

instance WriteQueueSTM TQ where
  waitWriteQueueSTM = writeableTQ
  writeQueueSTM = writeTQ

---

type ChanQ = Chan

newQueueChan :: IO (ChanQ a)
newQueueChan = newChan

instance ReadQueue Chan where
  readQueue = readChan

instance WriteQueue Chan where
  writeQueue = writeChan

instance QueueSize Chan where
  sizeMaxBound _ = -1
  readSizes _ = return (-1, -1)

---

type Q1 = TMVar

newQueue1 :: IO (Q1 a)
newQueue1 = atomically newEmptyTMVar

instance ReadQueue TMVar where
  readQueue = atomically . takeTMVar

instance WriteQueue TMVar where
  writeQueue q = atomically . putTMVar q

instance QueueSize TMVar where
  sizeMaxBound _ = 1
  readSizes q = atomically $ (,) <$> (emptySize <$> isEmptyTMVar q) <*> pure (-1)
    where emptySize empty = if empty then 0 else 1

instance ReadQueueSTM TMVar where
  waitReadQueueSTM = guard . not <=< isEmptyTMVar
  readQueueSTM = takeTMVar

instance WriteQueueSTM TMVar where
  waitWriteQueueSTM = guard <=< isEmptyTMVar
  writeQueueSTM = putTMVar
