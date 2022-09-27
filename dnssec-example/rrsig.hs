-- GHC packages
import Control.Monad (when)
import Data.Int (Int64)
import Data.String (fromString)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Text.Printf (printf)
import Data.Time (UTCTime, parseTimeM, defaultTimeLocale)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)

-- memory
import qualified Data.ByteArray as BA
import Data.ByteArray.Encoding (Base (Base64), convertFromBase)

-- cryptonite
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.RSA (PublicKey (..))
import Crypto.PubKey.RSA.Prim (ep)
import Crypto.Hash (Digest, hashWith)
import Crypto.Hash.Algorithms (SHA256 (..))

-- dns
import Network.DNS (ResourceRecord (..), TYPE (A, AAAA))
import qualified Network.DNS as DNS

-- local
import StatePut (runSPut)
import PutSIG (RRSIG_META (..), RRSIG_HEADER, putRRSIG_HEADER, putResourceRecordNC)


bytesFromB64 :: ByteString -> Either String ByteString
bytesFromB64 = convertFromBase Base64 . B8.filter (/= ' ')

getPubKey :: ByteString -> Either String PublicKey
getPubKey kb = case BS.uncons kb of
  Nothing          ->  Left "getPubKey: empty input"
  Just (b1, rest)
    | b1 > 0    -> do
        let (ex, key) = BS.splitAt (fromIntegral b1) rest
        Right PublicKey { public_size = BS.length key, public_n = beInteger key, public_e = beInteger ex }
    | otherwise -> do  {- case b1 == 0 -}
        let (exlen, rest2) = BS.splitAt 2 rest
            (ex, key) = BS.splitAt (fromIntegral $ beInteger exlen) rest2
        Right PublicKey { public_size = BS.length key, public_n = beInteger key, public_e = beInteger ex }

beInteger :: ByteString -> Integer
beInteger = os2ip {- RFC8017 os2ip definition -}
{-
beInteger = recurse 0
  where
    recurse a bs =
      case BS.uncons bs of
        Nothing  ->  a
        Just (b, nbs) | let na = a * 256 + fromIntegral b -> na `seq` recurse na nbs
 -}

getPubKeyB64 :: ByteString -> Either String PublicKey
getPubKeyB64 b64 = getPubKey =<< bytesFromB64 b64


data PKCS1
  = PKCS1SHA1
  | PKCS1SHA224
  | PKCS1SHA256
  | PKCS1SHA384
  | PKCS1SHA512
  deriving (Eq, Show)

{-
-- PKCS for RSA/SHA-XXX
-- https://datatracker.ietf.org/doc/html/rfc8017#section-9.2

         SHA-1:       (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
         SHA-224:     (0x)30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c || H.
         SHA-256:     (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
         SHA-384:     (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
         SHA-512:     (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
 -}
pkcs1Prefix :: PKCS1 -> ByteString
pkcs1Prefix tag = case tag of
  PKCS1SHA1    -> sha1
  PKCS1SHA224  -> sha224
  PKCS1SHA256  -> sha256
  PKCS1SHA384  -> sha384
  PKCS1SHA512  -> sha512
  where
    sha1    = BS.pack [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
    sha224  = BS.pack [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]
    sha256  = BS.pack [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
    sha384  = BS.pack [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
    sha512  = BS.pack [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]

stripRRSigPrefix :: PKCS1 -> ByteString -> Either String ByteString
stripRRSigPrefix pkcs1 s0 = do
  s1 <- stripP (BS.pack [0x00, 0x01]) s0
  let s2 = BS.dropWhile (== 0xff) s1
  s3 <- stripP (BS.pack [0x00]) s2
  stripP (pkcs1Prefix pkcs1) s3
  where
    stripP prefix = maybe (Left $ "stripRRSigPrefix: expected prefix " ++ show prefix) Right . BS.stripPrefix prefix

decodeSig :: PKCS1 -> ByteString -> ByteString -> Either String ByteString
decodeSig pkcs1 zskB64 sigB64 = do
  key <- getPubKeyB64 zskB64
  sig <- bytesFromB64 sigB64
  stripRRSigPrefix pkcs1 $ ep key sig

---

sha256sum :: ByteString -> Digest SHA256
sha256sum = hashWith SHA256

sha256sumBS :: ByteString -> ByteString
sha256sumBS = BA.pack . BA.unpack . hashWith SHA256

---

bsDump :: ByteString -> String
bsDump = concatMap (printf "%02x") . BS.unpack

---

checkRRSIG :: PKCS1 -> ByteString -> ByteString -> RRSIG_HEADER -> ResourceRecord -> Either String String
checkRRSIG pkcs1 zskB64 sigB64 rrsigH rr = do
  dec <- decodeSig pkcs1 zskB64 sigB64
  let sig = sha256sumBS $ runSPut $ putRRSIG_HEADER rrsigH <> putResourceRecordNC rr
  when (dec /= sig) $ Left  $ unlines ["checkRRSIG: signature mismatch:", bsDump dec, "  =/=", bsDump sig]
  Right $ "Good: " ++ bsDump sig

---

parseRRSIGTime :: String -> Maybe UTCTime
parseRRSIGTime s = parseTimeM False defaultTimeLocale "%Y%m%d%H%M%S%Z" (s ++ "UTC")

getRRSIGTimeInt :: String -> Maybe Int64
getRRSIGTimeInt s = floor . utcTimeToPOSIXSeconds <$> parseRRSIGTime s

getRRSIGTimeInt' :: String -> Int64
getRRSIGTimeInt' s = maybe (error $ "getRRSIGTimeInt': fail to parse: " ++ s) id $ getRRSIGTimeInt s

-----

{-
-- Domain Name System Security (DNSSEC) Algorithm Numbers
-- https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml

Number    Description                      Mnemonic              Zone Signing   Trans. Sec.   Reference

0         Delete DS                        DELETE                N              N             [RFC4034][proposed standard][RFC4398][proposed standard][RFC8078][proposed standard]
1         RSA/MD5 (deprecated)             RSAMD5                N              Y             [RFC3110][proposed standard][RFC4034][proposed standard]
2         Diffie-Hellman                   DH                    N              Y             [RFC2539][proposed standard]
3         DSA/SHA1                         DSA                   Y              Y             [RFC3755][proposed standard][RFC2536][proposed standard]
4         Reserved                                                                            [RFC6725][proposed standard]
5         RSA/SHA-1                        RSASHA1               Y              Y             [RFC3110][proposed standard][RFC4034][proposed standard]
6         DSA-NSEC3-SHA1                   DSA-NSEC3-SHA1        Y              Y             [RFC5155][proposed standard]
7         RSASHA1-NSEC3-SHA1               RSASHA1-NSEC3-SHA1    Y              Y             [RFC5155][proposed standard]
8         RSA/SHA-256                      RSASHA256             Y              *             [RFC5702][proposed standard]
9         Reserved                                                                            [RFC6725][proposed standard]
10        RSA/SHA-512                      RSASHA512             Y              *             [RFC5702][proposed standard]
11        Reserved                                                                            [RFC6725][proposed standard]
12        GOST R 34.10-2001                ECC-GOST              Y              *             [RFC5933][proposed standard]
13        ECDSA Curve P-256 with SHA-256   ECDSAP256SHA256       Y              *             [RFC6605][proposed standard]
14        ECDSA Curve P-384 with SHA-384   ECDSAP384SHA384       Y              *             [RFC6605][proposed standard]
15        Ed25519                          ED25519               Y              *             [RFC8080][proposed standard]
16        Ed448                            ED448                 Y              *             [RFC8080][proposed standard]
17-122    Unassigned
123-251   Reserved                                                                            [RFC4034][proposed standard][RFC6014][proposed standard]
252       Reserved for Indirect Keys       INDIRECT              N              N             [RFC4034][proposed standard]
253       private algorithm                PRIVATEDNS            Y              Y             [RFC4034][proposed standard]
254       private algorithm OID            PRIVATEOID            Y              Y             [RFC4034][proposed standard]
255       Reserved                                                                            [RFC4034][proposed standard]
 -}

{-
-- DNSSEC Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms
-- https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml

Value         Description         Status         Reference
0             Reserved            -              [RFC3658]
1             SHA-1               MANDATORY      [RFC3658]
2             SHA-256             MANDATORY      [RFC4509]
3             GOST R 34.11-94     OPTIONAL       [RFC5933]
4             SHA-384             OPTIONAL       [RFC6605]
5-255         Unassigned          -
 -}

-- iijZskOld :: PublicKey
-- Right iijZskOld = getPubKey =<< bytesFromB64 iijZskBytesOld

-- sigAold :: ByteString
-- Right sigAold = bytesFromB64 engSigAOld

-- iij.ad.jp.    86400  IN  DNSKEY  256 3 8
-- AwEAAeOWBqH2UB9KPS1vgt8xABUXQA9aEOl460b0rA+J46BgZK9lD4tn LRfkHpCNSxzQWQUcIziT8/cZ+I4Vd/U2Vnoqnhw34sFjbAXawwdntZM0 jTS3/Xnx3mtgUiySc+u3MBhuAe+4aSvwxJ/X+u6jZOJj+VgG6MBx1+oo z2lnnX31
b64IijZsk1 :: ByteString
b64IijZsk1 = B8.pack "AwEAAeOWBqH2UB9KPS1vgt8xABUXQA9aEOl460b0rA+J46BgZK9lD4tn LRfkHpCNSxzQWQUcIziT8/cZ+I4Vd/U2Vnoqnhw34sFjbAXawwdntZM0 jTS3/Xnx3mtgUiySc+u3MBhuAe+4aSvwxJ/X+u6jZOJj+VgG6MBx1+oo z2lnnX31"

-- iij.ad.jp.    86400  IN  DNSKEY  256 3 8
-- AwEAAeD+V7UXu0mzGaIRtZryR7qz/+evt1GX+pZJVgcVC9n67c8dzrv3 YrIuNUlRVKTOKcTOuwA6/I3oo5P/j+zTKzusqa9MyJuIXFzROsJ2kjCV KFVxB+L+rfQxhO+334fmFFehPouDew2kAPP6YKDufkkMwSfj/VUooXoN rqr42o97
b64IijZsk2 :: ByteString
b64IijZsk2 = B8.pack "AwEAAeD+V7UXu0mzGaIRtZryR7qz/+evt1GX+pZJVgcVC9n67c8dzrv3 YrIuNUlRVKTOKcTOuwA6/I3oo5P/j+zTKzusqa9MyJuIXFzROsJ2kjCV KFVxB+L+rfQxhO+334fmFFehPouDew2kAPP6YKDufkkMwSfj/VUooXoN rqr42o97"

-- iij.ad.jp.    86400  IN  DNSKEY  257 3 8
-- AwEAAd5lYXd3r4sru3TmsRNnQn7vG3R6HbGx1LSXOktO1GBbbTpUh0s5 lI6dBqbaL+NiaQ9nvI9r9InOXOIxW6UvU2Mvx0N0KRkeZvk4e4xmZx2I WxA7Nx+lQJyEjmGRdfNHgjAww99fycolKvm1fTunWwKtoqR6KsiiFDQW 8x1yYWJJhqGV0G2PTyQBUBLfyEaG15+a9jGAC907GOs5W3zHGKU0xbza q5BoddvHoNoUqKDnbCBG8qWunm/tXxSSelrlWLA5nDB19NQrxuGzCIpw 44WrqWANTFGmPQ61e+qr6RfBOGHgUFPsiYOi87vu/lKy2zZYB/W32A4P 2Sp3e8mzwfk=
b64IijKsk :: ByteString
b64IijKsk = B8.pack "AwEAAd5lYXd3r4sru3TmsRNnQn7vG3R6HbGx1LSXOktO1GBbbTpUh0s5 lI6dBqbaL+NiaQ9nvI9r9InOXOIxW6UvU2Mvx0N0KRkeZvk4e4xmZx2I WxA7Nx+lQJyEjmGRdfNHgjAww99fycolKvm1fTunWwKtoqR6KsiiFDQW 8x1yYWJJhqGV0G2PTyQBUBLfyEaG15+a9jGAC907GOs5W3zHGKU0xbza q5BoddvHoNoUqKDnbCBG8qWunm/tXxSSelrlWLA5nDB19NQrxuGzCIpw 44WrqWANTFGmPQ61e+qr6RfBOGHgUFPsiYOi87vu/lKy2zZYB/W32A4P 2Sp3e8mzwfk="

-- eng-blog.iij.ad.jp.  300  IN  RRSIG  A 8 4 300 20221102151005 20221003151005 34908 iij.ad.jp.
-- QEv8fD6+zGWJxVRwXN/4OQP/fJWjb8+zeKugVYdvGClgrFssNUTcx8SU yoPbRrW+xqZePxp7i1yGfBapZVq94mCR/x9W88gT5zl0pZ+pAAbfmg9a WD+/UU+27MgJxZFdHXIxBHSvoDHxsA4RihACCT9drk+Sueg2MbbwU38d dGM=
rrsigHeaderEngA :: RRSIG_HEADER
rrsigHeaderEngA =
  ( RRSIG_META
    { rrsigType = A
    , rrsigKeyAlg = 8
    , rrsigNumLabels = 4
    , rrsigTTL = 300
    , rrsigExpiration = getRRSIGTimeInt' "20221102151005"
    , rrsigInception  = getRRSIGTimeInt' "20221003151005"
    , rrsigKeyTag = 34908
    },
    B8.pack "iij.ad.jp.")

b64EncSigEngA :: ByteString
b64EncSigEngA = B8.pack "QEv8fD6+zGWJxVRwXN/4OQP/fJWjb8+zeKugVYdvGClgrFssNUTcx8SU yoPbRrW+xqZePxp7i1yGfBapZVq94mCR/x9W88gT5zl0pZ+pAAbfmg9a WD+/UU+27MgJxZFdHXIxBHSvoDHxsA4RihACCT9drk+Sueg2MbbwU38d dGM="

-- eng-blog.iij.ad.jp.  300  IN  RRSIG  AAAA 8 4 300 20221102151005 20221003151005 34908 iij.ad.jp.
-- g9al6v3uVnOkZeoLW24A80XUgKlECu+AaGJu+eZlhKZ8iHc+NEJAaa8l V4JY5Ty0p8qmBav4Wpvxt2w89q6qSg8C9y3tojPl6lwBTcVf8SqWUJGL QSv8o2T+N7Yq6Q4slQeP09W8aNdmW7ihAHqPIyN80VNTfNhVOk7bOBLR ESs=
rrsigHeaderEngAAAA :: RRSIG_HEADER
rrsigHeaderEngAAAA =
  ( RRSIG_META
    { rrsigType = AAAA
    , rrsigKeyAlg = 8
    , rrsigNumLabels = 4
    , rrsigTTL = 300
    , rrsigExpiration = getRRSIGTimeInt' "20221102151005"
    , rrsigInception  = getRRSIGTimeInt' "20221003151005"
    , rrsigKeyTag = 34908
    },
    B8.pack "iij.ad.jp.")

b64EncSigEngAAAA :: ByteString
b64EncSigEngAAAA = B8.pack "g9al6v3uVnOkZeoLW24A80XUgKlECu+AaGJu+eZlhKZ8iHc+NEJAaa8l V4JY5Ty0p8qmBav4Wpvxt2w89q6qSg8C9y3tojPl6lwBTcVf8SqWUJGL QSv8o2T+N7Yq6Q4slQeP09W8aNdmW7ihAHqPIyN80VNTfNhVOk7bOBLR ESs="

---

iijZsk1 :: PublicKey
Right iijZsk1 = getPubKey =<< bytesFromB64 b64IijZsk1

iijZsk2 :: PublicKey
Right iijZsk2 = getPubKey =<< bytesFromB64 b64IijZsk2

encSigEngA :: ByteString
Right encSigEngA = bytesFromB64 b64EncSigEngA

encSigEngAAAA :: ByteString
Right encSigEngAAAA = bytesFromB64 b64EncSigEngAAAA

decodedEngA1 :: Either String String
decodedEngA1 = bsDump <$> decodeSig PKCS1SHA256 b64IijZsk1 b64EncSigEngA

decodedEngA2 :: Either String String
decodedEngA2 = bsDump <$> decodeSig PKCS1SHA256 b64IijZsk2 b64EncSigEngA

decodedEngAAAA1 :: Either String String
decodedEngAAAA1 = bsDump <$> decodeSig PKCS1SHA256 b64IijZsk1 b64EncSigEngAAAA

decodedEngAAAA2 :: Either String String
decodedEngAAAA2 = bsDump <$> decodeSig PKCS1SHA256 b64IijZsk2 b64EncSigEngAAAA

---

-- eng-blog.iij.ad.jp.  300  IN  A  202.232.2.183
rrEngA :: ResourceRecord
rrEngA = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = DNS.classIN, rrtype = A, rdata = DNS.RD_A $ read "202.232.2.183" }

sigArgEngA :: ByteString
sigArgEngA = runSPut $ putRRSIG_HEADER rrsigHeaderEngA <> putResourceRecordNC rrEngA

sigEngA :: String
sigEngA = bsDump $ sha256sumBS sigArgEngA

checkEngA :: Either String String
checkEngA = checkRRSIG PKCS1SHA256 b64IijZsk2 b64EncSigEngA rrsigHeaderEngA rrEngA

-- eng-blog.iij.ad.jp.  300  IN  AAAA  2001:240:bb81::10:183
rrEngAAAA :: ResourceRecord
rrEngAAAA = ResourceRecord { rrname = fromString "eng-blog.iij.ad.jp.", rrttl = 300, rrclass = DNS.classIN, rrtype = AAAA, rdata = DNS.RD_AAAA $ read "2001:240:bb81::10:183" }

sigArgEngAAAA :: ByteString
sigArgEngAAAA = runSPut $ putRRSIG_HEADER rrsigHeaderEngAAAA <> putResourceRecordNC rrEngAAAA

sigEngAAAA :: String
sigEngAAAA = bsDump $ sha256sumBS sigArgEngAAAA

checkEngAAAA :: Either String String
checkEngAAAA = checkRRSIG PKCS1SHA256 b64IijZsk2 b64EncSigEngAAAA rrsigHeaderEngAAAA rrEngAAAA
