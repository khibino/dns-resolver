{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StandaloneDeriving #-}

module PutSIG where

-- GHC packages
import GHC.Generics (Generic)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LB

-- dnsext
import Data.IP (IPv4, fromIPv4, IPv6, fromIPv6b)
import DNS.Types (Domain, Mailbox, TYPE (..), fromTYPE, ResourceRecord (..), RData)
import DNS.Types.Internal (SPut, put8, put16, put32, putInt8, putSeconds, ResourceData (..), addBuilderPosition, putRData, CanonicalFlag (..))

import qualified DNS.Types as DNS

-- local
import StatePut (putDomainNC, putMailboxNC)
import StatePutGeneric (SPutI (sPut), genericSPut)


---

instance SPutI TYPE where
  sPut = put16 . fromTYPE

instance SPutI Word8 where
  sPut = put8

instance SPutI Word16 where
  sPut = put16

instance SPutI Word32 where
  sPut = put32

instance SPutI Int64 where
  sPut = put32 . fromIntegral

instance SPutI DNS.OData where
  sPut = error "SPutI.sPut: OData: must not happen"

instance SPutI a => SPutI [a] where
  sPut = mconcat . map sPut

instance SPutI IPv4 where
  sPut = mconcat . map putInt8 . fromIPv4

instance SPutI IPv6 where
  sPut = mconcat . map putInt8 . fromIPv6b

---

data RRSIG_META =
  RRSIG_META
  { rrsigType       :: !TYPE       -- ^ RRtype of RRset signed
  , rrsigKeyAlg     :: !Word8      -- ^ DNSKEY algorithm
  , rrsigNumLabels  :: !Word8      -- ^ Number of labels signed
  , rrsigTTL        :: !Word32     -- ^ Maximum origin TTL
  , rrsigExpiration :: !Int64      -- ^ Time last valid
  , rrsigInception  :: !Int64      -- ^ Time first valid
  , rrsigKeyTag     :: !Word16     -- ^ Signing key tag
  }
  deriving (Eq, Ord, Generic)

type RRSIG_HEADER = (RRSIG_META, Domain)

rrsigMeta :: RRSIG_HEADER -> RRSIG_META
rrsigMeta = fst

-- | Signing domain - Signer's name on RFC4034
rrsigZone :: RRSIG_HEADER -> Domain
rrsigZone = snd

putRRSIG_HEADER :: RRSIG_HEADER -> SPut
putRRSIG_HEADER (meta, sn) = genericSPut meta <> putDomainNC sn

---

{- instances without Name Compression -}
newtype RD_NS = RD_NS Domain deriving (Eq, Ord)
instance ResourceData RD_NS where
  resourceDataType _ = NS
  putResourceData _ (RD_NS d) = putDomainNC d
  getResourceData = error "getResourceData: unused in dnssec-example"
instance Show RD_NS where show (RD_NS d) = show d

newtype RD_CNAME = RD_CNAME Domain deriving (Eq, Ord)
instance ResourceData RD_CNAME where
  resourceDataType _ = CNAME
  putResourceData _ (RD_CNAME d) = putDomainNC d
  getResourceData = error "getResourceData: unused in dnssec-example"
instance Show RD_CNAME where show (RD_CNAME d) = show d

data RD_SOA = RD_SOA Domain Mailbox Word32 Word32 Word32 Word32 Word32 deriving (Eq, Ord, Show)
instance ResourceData RD_SOA where
  resourceDataType _ = SOA
  putResourceData _ (RD_SOA mn rn a b c d e) =
    mconcat [putDomainNC mn, putMailboxNC rn, put32 a, put32 b, put32 c, put32 d, put32 e]
  getResourceData = error "getResourceData: unused in dnssec-example"

newtype RD_PTR = RD_PTR Domain deriving (Eq, Ord)
instance ResourceData RD_PTR where
  resourceDataType _ = PTR
  putResourceData _ (RD_PTR d) = putDomainNC d
  getResourceData = error "getResourceData: unused in dnssec-example"
instance Show RD_PTR where show (RD_PTR d) = show d

data RD_MX = RD_MX Word16 Domain deriving (Eq, Ord, Show)
instance ResourceData RD_MX where
  resourceDataType _ = MX
  putResourceData _ (RD_MX pref exch) = put16 pref <> putDomainNC exch
  getResourceData = error "getResourceData: unused in dnssec-example"

putResourceRecordNC :: ResourceRecord -> SPut
putResourceRecordNC rr = mconcat [
    putDomainNC $ rrname rr
  , put16 (fromTYPE $ rrtype rr)
  , put16 $ rrclass rr
  , putSeconds $ rrttl rr
  , putResourceRData $ rdata rr
  ]
  where
    putResourceRData :: RData -> SPut
    putResourceRData rd = do
        addBuilderPosition 2 -- "simulate" putInt16
        rDataBuilder <- putRData Canonical rd
        let rdataLength = fromIntegral . LB.length . BB.toLazyByteString $ rDataBuilder
        let rlenBuilder = BB.int16BE rdataLength
        return $ rlenBuilder <> rDataBuilder
