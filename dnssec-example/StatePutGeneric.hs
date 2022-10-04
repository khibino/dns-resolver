{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeOperators #-}

module StatePutGeneric where

import GHC.Generics (Generic, Rep, U1, K1 (..), M1 (..), (:+:)(..), (:*:)(..), from)

import StatePut (SPut)

class SPutI a where
  sPut :: a -> SPut

class GSPut f where
  gsPut :: f x -> SPut

genericSPut :: (Generic a, GSPut (Rep a)) => a -> SPut
genericSPut = gsPut . from

instance GSPut U1 where
  gsPut = mempty

instance SPutI a => GSPut (K1 i a) where
  gsPut (K1 x) = sPut x

instance GSPut f => GSPut (M1 i c f) where
  gsPut (M1 x) = gsPut x

instance (GSPut f, GSPut g) => GSPut (f :+: g) where
  gsPut (L1 x) = gsPut x
  gsPut (R1 y) = gsPut y

instance (GSPut f, GSPut g) => GSPut (f :*: g) where
  gsPut (x :*: y) = gsPut x <> gsPut y
