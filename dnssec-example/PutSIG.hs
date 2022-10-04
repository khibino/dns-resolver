{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StandaloneDeriving #-}

module PutSIG where

-- GHC packages
import GHC.Generics (Generic)
import Data.Int (Int64)
import Data.Word (Word8, Word16, Word32)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LB

-- dns
import Data.IP (IPv4, fromIPv4, IPv6, fromIPv6b)
import Network.DNS (Domain, TYPE, fromTYPE, RData(..), ResourceRecord (..))
import qualified Network.DNS as DNS

-- local
import StatePut (SPut, put8, put16, put32, putInt8, putByteString, putDomainNC, putMailboxNC, addPositionW)
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

instance SPutI ByteString where
  sPut = putByteString

instance SPutI DNS.OData where
  sPut = error "SPutI.sPut: OData: must not happen"

instance SPutI DNS.RD_RRSIG where
  sPut = error "SPutI.sPut: RRSIG: must not happen"

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

deriving instance Generic RData

putRData :: RData -> SPut
putRData rd = case rd of
  RD_NS                nsdname -> putDomainNC nsdname
  RD_CNAME               cname -> putDomainNC cname
  RD_SOA       mn mr a b c d e -> putDomainNC mn <> putMailboxNC mr <> sPut [a, b, c, d, e]
  RD_PTR              ptrdname -> putDomainNC ptrdname
  RD_MX              pref exch -> mconcat [put16 pref, putDomainNC exch]
  RD_DNAME                  {} -> undefined
  RD_OPT                    {} -> error "putRData.RD_OPT: must not happen"
  RD_DS                     {} -> error "putRData.RD_DS: must not happen"
  RD_CDS                    {} -> error "putRData.RD_CDS: must not happen"
  RD_RRSIG                  {} -> error "putRData.RD_RRSIG: must not happen"
  RD_NSEC                   {} -> undefined
  RD_NSEC3                  {} -> undefined

  _others                      -> genericSPut rd

putResourceRecordNC :: ResourceRecord -> SPut
putResourceRecordNC rr = mconcat [
    putDomainNC $ rrname rr
  , put16 (fromTYPE $ rrtype rr)
  , put16 $ rrclass rr
  , put32 $ rrttl rr
  , putResourceRData $ rdata rr
  ]
  where
    putResourceRData :: RData -> SPut
    putResourceRData rd = do
        addPositionW 2 -- "simulate" putInt16
        rDataBuilder <- putRData rd
        let rdataLength = fromIntegral . LB.length . BB.toLazyByteString $ rDataBuilder
        let rlenBuilder = BB.int16BE rdataLength
        return $ rlenBuilder <> rDataBuilder
