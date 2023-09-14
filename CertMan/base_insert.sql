INSERT INTO TB_CERT_PROFILE (NUM,Name,Type,Version,NotBefore,NotAfter,ExtUsage,Hash,DNTemplate) VALUES (1,'ROOT_CA',0,2,0,3650,0,'SHA256','#CSR');
INSERT INTO TB_CERT_PROFILE (NUM,Name,Type,Version,NotBefore,NotAfter,ExtUsage,Hash,DNTemplate) VALUES (2,'SSL_CA',0,2,0,3000,0,'SHA256','#CSR');
INSERT INTO TB_CERT_PROFILE (NUM,Name,Type,Version,NotBefore,NotAfter,ExtUsage,Hash,DNTemplate) VALUES (3,'SSL_Server',0,2,0,365,0,'SHA256','#CSR');
INSERT INTO TB_CERT_PROFILE (NUM,Name,Type,Version,NotBefore,NotAfter,ExtUsage,Hash,DNTemplate) VALUES (4,'TSP Server',0,2,0,365,0,'SHA256','#CSR');
INSERT INTO TB_CERT_PROFILE (NUM,Name,Type,Version,NotBefore,NotAfter,ExtUsage,Hash,DNTemplate) VALUES (5,'OCSP Server',0,2,0,365,0,'SHA256','#CSR');
INSERT INTO TB_CRL_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (1,1,0,'crlNumber','auto');
INSERT INTO TB_CRL_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (2,1,1,'issuingDistributionPoint','URI$http://www.test.com/crl.crl');
INSERT INTO TB_CRL_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (3,1,0,'authorityKeyIdentifier','ISSUER#SERIAL#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (1,1,1,'basicConstraints','CA');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (2,1,1,'keyUsage','keyCertSign#cRLSign');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (3,1,0,'subjectKeyIdentifier','');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (4,2,0,'authorityInfoAccess','OCSP$URI$http://ocsp.test.com');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (5,2,0,'authorityKeyIdentifier',NULL);
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (6,2,1,'basicConstraints','CA#0');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (7,2,0,'crlDistributionPoints','URI$http://crl.test.com/SSL_CA.crl');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (8,2,0,'extendedKeyUsage','serverAuth#clientAuth');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (9,2,1,'keyUsage','digitalSignature#keyCertSign#cRLSign');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (10,2,0,'certificatePolicies','OID$2.5.29.32.0#CPS$https://www.test.com/CPS#UserNotice$#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (11,2,0,'subjectKeyIdentifier','');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (12,3,0,'authorityInfoAccess','OCSP$URI$http://ocsp.test.com#caIssuer$URI$http://ca.test.com');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (13,3,0,'authorityKeyIdentifier',NULL);
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (14,3,0,'basicConstraints','EE');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (15,3,0,'extendedKeyUsage','serverAuth#clientAuth');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (16,3,1,'keyUsage','digitalSignature#keyEncipherment');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (17,3,0,'certificatePolicies','OID$1.2.3.4#CPS$http://www.test.com/CPS#UserNotice$#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (18,3,0,'subjectKeyIdentifier','');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (19,3,0,'subjectAltName','DNS$*.www.test.com#DNS$www.test.com');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (20,4,0,'authorityKeyIdentifier','ISSUER#SERIAL#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (21,4,0,'crlDistributionPoints','URI$http://tsp.test.com/crl.crl');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (22,4,1,'extendedKeyUsage','timeStamping');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (23,4,1,'keyUsage','digitalSignature#nonRepudiation');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (24,4,1,'certificatePolicies','OID$1.2.3.4#CPS$http://tsp.test.com/cps.html#UserNotice$This is test TSP user notice#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (25,4,0,'subjectKeyIdentifier','');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (26,5,0,'authorityKeyIdentifier','ISSUER#SERIAL#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (27,5,0,'crlDistributionPoints','URI$http://ocsp.test.com/crl.crl');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (28,5,1,'extendedKeyUsage','OCSPSigning');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (29,5,1,'keyUsage','digitalSignature#nonRepudiation');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (30,5,1,'certificatePolicies','OID$1.2.3.4#CPS$http://ocsp.test.com/cps.html#UserNotice$This is test OCSP user notice#');
INSERT INTO TB_CERT_PROFILE_EXTENSION (Seq,ProfileNum,Critical,SN,Value) VALUES (31,5,0,'subjectKeyIdentifier','');
INSERT INTO TB_CRL_PROFILE (Num,Name,Version,ThisUpdate,NextUpdate,Hash) VALUES (1,'CRL Profile',1,0,10,'SHA256');

