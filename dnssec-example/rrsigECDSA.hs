-- GHC packages
import Control.Monad (unless)
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
import Crypto.PubKey.ECC.Types (CurveName)
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import Crypto.PubKey.ECC.ECDSA (PublicKey)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Error (CryptoFailable (..))
import Crypto.Hash (Digest, hashWith)
import Crypto.Hash.Algorithms (SHA256 (..))

-- dns
import DNS.Types (ResourceRecord (..), TYPE (..))
import qualified DNS.Types as DNS
import DNS.Types.Internal (runSPut)

-- local
import PutSIG (RRSIG_META (..), RRSIG_HEADER, putRRSIG_HEADER, putResourceRecordNC)


cryptoFailableEither :: CryptoFailable a -> Either String a
cryptoFailableEither (CryptoFailed e) = Left $ show e
cryptoFailableEither (CryptoPassed x) = Right x

bytesFromB64 :: ByteString -> Either String ByteString
bytesFromB64 = convertFromBase Base64 . B8.filter (/= ' ')

getPubKeyECC :: CurveName -> ByteString -> Either String PublicKey
getPubKeyECC cn kbs = do
  unless (BS.length kbs == size * 2) $
    Left $ "getPubKeyECC: invalid length of encoded pubkey: " ++
    "expect " ++ show (size * 2) ++ ", " ++
    "actual " ++ show (BS.length kbs)
  unless (ECC.isPointValid curve point) $
    Left $ "getPubKeyECC: not valid point on curve " ++ show cn
  Right $ ECDSA.PublicKey curve point
  where
    curve = ECC.getCurveByName cn
    size = curveSizeBytes curve
    (xb, yb) = BS.splitAt size kbs
    point = ECC.Point (os2ip xb) (os2ip yb)

curveSizeBytes :: ECC.Curve -> Int
curveSizeBytes curve = (ECC.curveSizeBits curve + 7) `div` 8

---

sha256sum :: ByteString -> Digest SHA256
sha256sum = hashWith SHA256

sha256sumBS :: ByteString -> ByteString
sha256sumBS = BA.pack . BA.unpack . hashWith SHA256

---

bsDump :: ByteString -> String
bsDump = concatMap (printf "%02x") . BS.unpack


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

-- salesforce.com.    3600  IN  DNSKEY  256 3 13
-- Y2q4vpoBYkeRbvsDMzpEJs10GEPEtu90hlAVIlD9XD8nnpcEM4WOVBgR 0/fOjavvw5mkwrgHb1nylySNNthBag==
b64SalesforceZsk :: ByteString
b64SalesforceZsk = B8.pack "Y2q4vpoBYkeRbvsDMzpEJs10GEPEtu90hlAVIlD9XD8nnpcEM4WOVBgR 0/fOjavvw5mkwrgHb1nylySNNthBag=="

-- salesforce.com.    3600  IN  DNSKEY  257 3 13
-- V/8mE5hPH+3R9Rv+TPVp5kfLPGhBnRd4agfviI7tG5xCq4XWpHMA2Qm5 CycAz43vuzqlEieYEYkp4zLe7Mo5UQ==
b64SalesforceKsk :: ByteString
b64SalesforceKsk = B8.pack "V/8mE5hPH+3R9Rv+TPVp5kfLPGhBnRd4agfviI7tG5xCq4XWpHMA2Qm5 CycAz43vuzqlEieYEYkp4zLe7Mo5UQ=="


salesforceZsk :: PublicKey
Right salesforceZsk = getPubKeyECC ECC.SEC_p256r1 =<< bytesFromB64 b64SalesforceZsk

-- help.salesforce.com.  300  IN  CNAME  help.salesforce.com.00d30000000xsfgeas.live.siteforce.com.
rrHelpsfCNAME :: ResourceRecord
rrHelpsfCNAME = ResourceRecord { rrname = fromString "help.salesforce.com.", rrttl = 300, rrclass = DNS.classIN, rrtype = CNAME, rdata = DNS.rd_cname $ fromString "help.salesforce.com.00d30000000xsfgeas.live.siteforce.com." }

-- help.salesforce.com.  300  IN  RRSIG  CNAME 13 3 300 20221201204626 20221002201307 2317 salesforce.com.
-- +CGXyQkuElGNc7FpDa0sO0ya7x/B/7DGhRfKOWSBGgshlokxUukOJHz2 T7+xdoNv2mpS2bTOK5LpJY2FS9e3kQ==
rrsigHeaderHelpsfCNAME :: RRSIG_HEADER
rrsigHeaderHelpsfCNAME =
  ( RRSIG_META
    { rrsigType = CNAME
    , rrsigKeyAlg = 13
    , rrsigNumLabels = 3
    , rrsigTTL = 300
    , rrsigExpiration = getRRSIGTimeInt' "20221201204626"
    , rrsigInception  = getRRSIGTimeInt' "20221002201307"
    , rrsigKeyTag = 2317
    },
    fromString "salesforce.com.")

b64EncSigHelpsfCNAME :: ByteString
b64EncSigHelpsfCNAME = B8.pack "+CGXyQkuElGNc7FpDa0sO0ya7x/B/7DGhRfKOWSBGgshlokxUukOJHz2 T7+xdoNv2mpS2bTOK5LpJY2FS9e3kQ=="

sigHelpsfCNAME :: ByteString
Right sigHelpsfCNAME = bytesFromB64 b64EncSigHelpsfCNAME

sigArgHelpsfCNAME :: ByteString
sigArgHelpsfCNAME = runSPut $ putRRSIG_HEADER rrsigHeaderHelpsfCNAME <> putResourceRecordNC rrHelpsfCNAME

verifyHelpsfCNAME :: Either String Bool
verifyHelpsfCNAME = do
  sig <- getSig
  return $ ECDSA.verify SHA256 pubkey sig sigArgHelpsfCNAME
  where
    pubkey = salesforceZsk
    curve = ECDSA.public_curve pubkey
    size = curveSizeBytes curve
    (rb, sb) = BS.splitAt size sigHelpsfCNAME
    getSig = do
      unless (BS.length sigHelpsfCNAME == size * 2) $
        Left "verifyHelpsfCNAME: invalid length of signature"
      return $ ECDSA.Signature (os2ip rb) (os2ip sb)

-- dnsops.jp.    10800  IN  DNSKEY  257 3 13 wX/AaeBy+0KCanTpMaByOC740ozgWECbZYRrc2WF81ko2PKZHZK5zNGq Z2L4PhAqbrqdJmuWRcsPpSsP+wrKaQ==
-- dnsops.jp.    10800  IN  DNSKEY  256 3 13 G3BFa1ybRrYpmr67UvKaaNYkxmO27FQx3wcK+LdNgXCE121ZRI+eXaDh ft2IXS9mpiafGu3L5dZbOTD5EdU54w==
-- dnsops.jp.    10800  IN  DNSKEY  256 3 13 Q1EPKWpkOezNGOcZMauZbi9+khJGN3HpF8RBm2XOybDtkUmvsGGneVj5 Mv5Hr6gCNNZ8HV7V+F2zGKJXSmDPoA==
-- dnsops.jp.    10800  IN  DNSKEY  256 3 13 ZuA9MLgG3gJmd8dyO6DjV9ymkhm0FBGmwtCyaynOFWSBiGfg1q3qZcVY l/ALzV8q7o2bMYtSrdnDE6Vbcu6i7g==
-- dnsops.jp.    10800  IN  DNSKEY  256 3 13 93t+rkxNKN5Xxtv7Klpy7Cxa0gc+zDLDQ1PsdaBanoHol821nz4NL7DO SQ3XZ6HDIpJMXnHQORW0jqG4a7DMOQ==

-- dnsops.jp.    300  IN  A  210.171.226.59

-- dnsops.jp.    300  IN  RRSIG  A 13 2 300 20221119230002 20221020230002 17855 dnsops.jp. n7yXFqHH2JE588w6vB88fKl+Nzs+oxSSLe0bKmcbXj8MFQdWm/l5tkUM pOIhQpAzz6uGKoHDB/1e/VQ3bhnYAQ==
-- dnsops.jp.    300  IN  RRSIG  A 13 2 300 20221119230002 20221020230002 65298 dnsops.jp. W7y3NDJexIjn+mij8FTbrtH37LZCdzJlRD+fMHG5QCXmBAiADrTPwm6a 592iWJGYbnl0LMC6f/7/PIEAIi1BbA==


-- mofa.go.jp.    86400  IN  RRSIG  TXT 8 3 86400 20221028085422 20221024075629 35808 mofa.go.jp. IYoTZ1R/ejIKfVI0LAKLxGWeI8DB8WackByYQIg/CzrfPiDCaQRjBV/A 0cz4wuaT7uTV1Nw6Gc+pd4LnJwOKfcYS8YVfwWhZ27foqH8lmsXqZqOR 6r2B8uF3pq1cjzaeVISks8uHtPGvGk/sjy+j0xaVeXV3RykqZFRcaiII 0/V7PnyadF5onMy6ZEFSHAG4dix+Wc6ebhc9Phr1mUlLnDRW+jMPPjGk M6VLx+rB0RBPIciCwIwwZFiOqg0bltPJn1K8NqS8C50AHDfzbcD48VbW TNCuF1ayX/IrGqS6ii8Dl1fe4q+HmoAEMKH+mgWEaDlkkh3sDabo9YIZ FOy+uw==
-- mofa.go.jp.    900  IN  RRSIG  NSEC3PARAM 8 3 900 20221028085422 20221024075629 35808 mofa.go.jp. f3EJIfQT5TMN8QRgkX4TRp5bpvo5IEXKqPM2M05bFdzDJiI+eM96qRRz gWeM32H5ii4uPkiDAiJf3JwBWoM3bYLpWNqiYWiubQoq/nprvrriQM2d YiJyZ7Oi2sPEvphn30253kQ8LKSyyEvEbXvhLuR7sI304QD/l8jIBkcm O1bJivhRlJsZ56GnKlu8DoKlNN1Avn5VaRUkaj30Xe3Nz4ZtkLSQjAN1 kCbaBo8040+xHdFyGx5WmUqXsXyLrWW17cOFdVLDppvuWOcdHq7V7mQy XTW2O+SUOYJRJKb3L2L+xVGoJTi+BmG+mGeryf099ELGb9YYWCupXDoP sFnuyA==
-- mofa.go.jp.    86400  IN  RRSIG  NS 8 3 86400 20221028075533 20221024070333 35808 mofa.go.jp. Z50kNKD2A4IazKoUlwbIFzh529UO+vorr99scL0eabfdOjEfTS0hCAjp INkix9wCgJ+llP24AOHf2tzCVpptkYoj6v7dDgjCjEbXdF9MLUg7G5pw nQ8JPndvzi4ggrew1dJMRd429UMvo7zBEmFzscoaLgezeirkwEvnyCXZ eJWgICJALD2s814slbSnZMTUG8u9VjRbJ/LzBh3c7+UqpQ0dHszgsyfr EGy1jPokRBJrKA0DkXLDyztjIrdqkbYU2IvWTUbWxy/bIfoz8X16wX8j bf9aKw/4WUUPFuQy2cLS6xWdDjG4ktxBRCeOZPN+Is+BUmzytpAawN4f GVQZZA==
-- mofa.go.jp.    86400  IN  RRSIG  MX 8 3 86400 20221028085422 20221024075629 35808 mofa.go.jp. jktQha886tgnsqMUMqDAWgyAyQ877QZWocCVgCDLK6hd0N6nJzAd9f8i sP77YlFK7Zvui6nn37YsDl/YMurKrwjM/zQjJ9WNaFVQpSS9Cs0jEGGS YPkdaC43Qx8ZJMF1/yiAIrUU1PCemXr6PvfGrVP2C/9snlEeaRWL7zdZ q/T+7B6AjZ9qxE74/t4Hn0Anva0MbeTCMnu4P6WrlxOWRkCWZnhD1hpy yjeynbQ0Pa0nei60vAHx2UorHIsIbtC1TlfB0grIxQXu0Qz7r5bnSyKR FZjp6OJZ1kKfmc4C5xbGmlD5O+yLxaPq66XUCR35+ZzlDU82+a/Y3DtL ryfINA==
-- mofa.go.jp.    86400  IN  RRSIG  SOA 8 3 86400 20221028103846 20221024093846 35808 mofa.go.jp. AgX/2GvlLstumntXvYFBYD6D0xSe42lrQzIGGwQaIXBCrIISOR8lJoDf diZIa6mqbd4K2p57ddFNdQowE0xfa5tA8gzwK2V6aMgwBE2nme/QzbDQ HZbogsDv7C/IKC+I3AlzC6pEBYDWmZM53QSI3pLZ2BnHPPd7ruqkRH3W b/saEPKh4VcURUCwVDbGCFYuuKWgQHc51Ck5Q53lusftD7vqHa/KSlH7 8yJhDCBswSoLPRkT4sPb7ry5S8iKYQti9jDvQyZGT304Uuc6m6wtCs0S GDuviDWH+b4ouDZvJHrUl0RQ6SaOzUCF4/swaDUXOwGlGxaQpGw3y9SR A7B88Q==
-- mofa.go.jp.    172800  IN  RRSIG  DNSKEY 8 3 172800 20221028071952 20221024062524 35808 mofa.go.jp. uFgbSIeSBxLlntnDZm9iwPmc6STS+pJb/HqnIKV2nwW3Q1TzutTBZhDT DGyFdqt3W3CS0pv7igqnk8PWDbRuUZPiiVSKcb71UahycQv8hH5xrL30 b/iIE2T23l//G4nDfU/ncMyTYnMY2dI+k2mJbJ9El14QK05G4Miw3+25 RqavBf69BvvcnJSJ5kAtPwIBtQ2KgM7sq1OdvL/BnCmwbKGRQcDP7xwn aZ+NFYoskrU8oxdOoZz1HWUZxtOL1500fvWzPcl/RnmlaCRgnRVEQKnX ji1ptnsjS9aAfp26+FmiLH7e5HIvaOB0gW9J6vbjT7XGAKRDiERBOV6L Ht/mNA==
-- mofa.go.jp.    172800  IN  RRSIG  DNSKEY 8 3 172800 20221028071952 20221024062524 24691 mofa.go.jp. rJPWbT0TIdJlMdFN1pzobnBfN/5/gWn8nrHUlIH+t37XdfWyv+wOT8En ok9doJpw5cHkRr0Rqch8EfJo2S1T7S1AsNrGLRJO+cH1nSHzYBDejnZy fECdwcHfaDje+zObayzn5yT+wbVIU7LSR7XDuWJUD4HqgrZ6t5oSUq/6 b4Oatn1lGHxMQR9kyCUr9Qt5OOS0cqgBPKYbjYdT/6K2/ntmrW8EuSwj Cq2guuQF/PpWmN37HYSQlMN+KV1PYdVoZoN438oP4dACk83t9kNECbVj 8B0nIU/HOMCDadry7x87A8d+u121k5bo9UNfhrcFsuoSqIA3ywloFpoD Alwg+Q==


-- mofa.go.jp.    172800  IN  DNSKEY  256 3 8 AwEAAeukh8jJtnc7riZVnpJBtoSffkieTpz0yxaSZBluoLmFbfLY72yg wjRmsNBAU/RrVZ09KZg5JJL8qIBRDf9ASwKkBxGpapjC1vk8wDSn5xCI MoPrzjsifImasn/I3dY/2IEugTJi5EmWck+YsHHtJcPdw4z7vB4NN77f NqfhRCsZV3QhLlMgMgxuf+66jRrZFMF/phZLencUVon+LvWpHaVhOk4e R5dmTWTSjpCh9bgVDjWMu9DZEJ3815OLa0b9fu2IoX3+3QaD2Qs8Oe0i QlSnvBZj95AcSBwZxkQC9lWm7DeVtFqRwPUlRwmIrG0KmNuiI1HBlBbA zX6EP6cNr0M=
-- mofa.go.jp.    172800  IN  DNSKEY  257 3 8 AwEAAdnt8PPuahkVU6yefTEusYFvi/2gAGeLmFOC5QGt3GNDzhTgMqJd OoX5R8gZX7q4W12lESch54KIv4oDs/T8vx6fEnGOkqOaoesJWKe6vHrf CCSH2MVLcmgqZSngl+iOQGcG0FYsiImPmciPLlNQ3b3OyfnOtIHxzF1q ItRalrtj4/8Nz3i32GWZaff/1CUA1c69PVbn2pb4l2phT6qGzVMJ9iPH TAWQLD5+VVUS8tG/ZFqvnK5zKp0Frn3OnsLqDx4m9+yCPoubd2V9f2k1 ReGvRXJw96W8oB+376cUAzxCeXO0FbtqDpbEnC9L0gTg4mV+k0OVrUSb 1PHS5hLO8Ak=
-- mofa.go.jp.    172800  IN  DNSKEY  256 3 8 AwEAAbAwt7lwSx3Nb245yEaP7wYA47uI0QiCEsmcs1p99IhHFdGdieFz UQZzwuycFVfm9EqfoZa4sw7zzNi5ZSwSmj/KLMb8ow2o875Kshaa1Qom Ea4hpHYKz6ZtdVjKjqV1WaGFeW4FKfCHZQQ1a+OPb+rqoINmpC2fsNHM 5SOUSuLIvSC/GpIYwwPXeB+w7z5FNlA6dUSlzEwRew5xisfj/FH7bQY4 ukdKOEHhzjlfFiA6mgWG8td65UWMXT8ditRriTD4UTr0hkmDHTrAFfNz 5YcN21+Vgce2aIDn/3FwB4BWi1J0engnsqmLvzWiCkCpsYkxvEz/qW46 C00M6a1hmfM=
-- mofa.go.jp.    172800  IN  DNSKEY  256 3 8 AwEAAcvp5IOnQ5j9WIcZOLPVZS79pYh8khGr7IAg3e38Aw/5mryUJ0uO 4CdzbBEMaeo08uJ+ufFC40UbQ4naprcPjywZkMDlzvKQgv2flQCWfwG3 9MWrz4cIFKqc80Rcx4LTEURSD3lf1plkR6qL6DKZ2BDAziKJs+oDwfSv eN1qUVfbWuPnHZLBF94Lq3bkam9ojfIo1H+lLYxec7E73PRhHioX4H3p 9sKMJmiHaoG6fUnCPhbs48RELnVvIx8NleYoQkS9PCor+hg4cnN1l5xn uCVDCXTD4nOrEkBqqg2Lxw36LAj5fr5ygWkGJa03NldF01U7CKjTHpJa fZvgm44KWy8=
