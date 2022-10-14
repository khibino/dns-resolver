{-# LANGUAGE FlexibleInstances #-}

module StatePut where

import Data.String (fromString)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Short as Short

import DNS.Types (Domain, Mailbox, origName)
import DNS.Types.Internal (put8, putLenShortByteString)
import qualified DNS.Types.Internal as DNS


type SPut = DNS.SPut

-- In the case of the TXT record, we need to put the string length
-- fixme : What happens with the length > 256 ?
putByteStringWithLength :: BS.ByteString -> SPut
putByteStringWithLength bs = putLenShortByteString $ Short.toShort bs

rootDomain :: ByteString
rootDomain = fromString "."

putDomainNC :: Domain -> SPut
putDomainNC dom = putDomainNC' '.' $ origName dom

putMailboxNC :: Mailbox -> SPut
putMailboxNC dom = putDomainNC' '@' $ origName dom

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
