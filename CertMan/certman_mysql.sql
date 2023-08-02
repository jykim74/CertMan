DROP SEQUENCE SEQ_TB_CRL_PROFILE_EXTENSION;
DROP SEQUENCE SEQ_TB_CERT_PROFILE_EXTENSION;
DROP SEQUENCE SEQ_TB_KMS;
DROP SEQUENCE SEQ_TB_CRL;
DROP SEQUENCE SEQ_TB_ADMIN;
DROP SEQUENCE SEQ_TB_TSP;
DROP SEQUENCE SEQ_TB_REQ;
DROP SEQUENCE SEQ_TB_KEY_PAIR;
DROP SEQUENCE SEQ_TB_SIGNER;
DROP SEQUENCE SEQ_TB_USER;
DROP SEQUENCE SEQ_TB_CERT;
DROP SEQUENCE SEQ_TB_REVOKED;
DROP SEQUENCE SEQ_TB_CONFIG;
DROP SEQUENCE SEQ_TB_AUDIT;

DROP TABLE TB_CRL_PROFILE_EXTENSION;
DROP TABLE TB_CERT_PROFILE_EXTENSION;
DROP TABLE TB_KMS;
DROP TABLE TB_KMS_ATTRIB;
DROP TABLE TB_CRL;
DROP TABLE TB_ADMIN;
DROP TABLE TB_TSP;
DROP TABLE TB_REQ;
DROP TABLE TB_KEY_PAIR;
DROP TABLE TB_AUDIT;
DROP TABLE TB_CERT_PROFILE;
DROP TABLE TB_CRL_PROFILE;
DROP TABLE TB_SIGNER;
DROP TABLE TB_USER;
DROP TABLE TB_CERT;
DROP TABLE TB_AUTH;
DROP TABLE TB_REVOKED;
DROP TABLE TB_CONFIG;


CREATE SEQUENCE SEQ_TB_CRL_PROFILE_EXTENSION;
CREATE SEQUENCE SEQ_TB_CERT_PROFILE_EXTENSION;
CREATE SEQUENCE SEQ_TB_KMS;
CREATE SEQUENCE SEQ_TB_CRL;
CREATE SEQUENCE SEQ_TB_ADMIN;
CREATE SEQUENCE SEQ_TB_TSP;
CREATE SEQUENCE SEQ_TB_REQ;
CREATE SEQUENCE SEQ_TB_KEY_PAIR;
CREATE SEQUENCE SEQ_TB_AUDIT;
CREATE SEQUENCE SEQ_TB_SIGNER;
CREATE SEQUENCE SEQ_TB_USER;
CREATE SEQUENCE SEQ_TB_CERT;
CREATE SEQUENCE SEQ_TB_REVOKED;
CREATE SEQUENCE SEQ_TB_CONFIG;


CREATE TABLE IF NOT EXISTS TB_CRL_PROFILE_EXTENSION (
	Seq			INT NOT NULL AUTO_INCREMENT,
	ProfileNum	INT,
	Critical	INT,
	SN			VARCHAR(64),
	Value		VARCHAR(512),
	PRIMARY KEY(Seq)
);

CREATE TABLE IF NOT EXISTS TB_CERT_PROFILE_EXTENSION (
	Seq	INT NOT NULL AUTO_INCREMENT,
	ProfileNum	INT,
	Critical	INT,
	SN	VARCHAR(64),
	Value VARCHAR(512),
	PRIMARY KEY(Seq)	
);


CREATE TABLE IF NOT EXISTS TB_KMS (
	SEQ	INT NOT NULL PRIMARY KEY AUTO_INCREMENT UNIQUE,
	REGTIME	INT,
	STATE	INT,
	TYPE	INT,
	ALGORITHM	INT,
	ID	VARCHAR(256),
	INFO	VARCHAR(256)
);


CREATE TABLE IF NOT EXISTS TB_KMS_ATTRIB (
	NUM	INT,
	TYPE	INT,
	VALUE	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_CRL (
	Num	INT PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	IssuerNum	INT,
	signAlg	VARCHAR(256),
	CRLDP	VARCHAR(256),
	CRL	Text
);

CREATE TABLE IF NOT EXISTS TB_ADMIN (
	Seq	INT PRIMARY KEY AUTO_INCREMENT,
	Status	INT,
	Type	INT,
	Name	VARCHAR(256),
	Password	VARCHAR(256),
	Email	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_TSP (
	SEQ	INT NOT NULL PRIMARY KEY AUTO_INCREMENT UNIQUE,
	RegTime	INT,
	Serial	INT,
	SrcHash	VARCHAR(256),
	Policy	VARCHAR(256),
	TSTInfo	VARCHAR(256),
	Data	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_REQ (
	SEQ	INT PRIMARY KEY AUTO_INCREMENT,
	REGTIME	INT,
	KEY_NUM	INT,
	NAME	VARCHAR(256),
	DN	VARCHAR(256),
	CSR	Text,
	HASH	VARCHAR(256),
	Status	INT
);

CREATE TABLE IF NOT EXISTS TB_KEY_PAIR (
	NUM	INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	ALGORITHM	VARCHAR(256),
	NAME	VARCHAR(256),
	PUBLIC	Text,
	PRIVATE	Text,
	PARAM	VARCHAR(256),
	Status	INT
);

CREATE TABLE IF NOT EXISTS TB_AUDIT (
	Seq	INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	Kind	INT,
	Operation	INT,
	UserName	VARCHAR(256),
	Info	VARCHAR(256),
	MAC	VARCHAR(256)
);


CREATE TABLE IF NOT EXISTS TB_CERT_PROFILE (
	NUM	INT,
	Name	VARCHAR(256),
	Type	INT,
	Version	INT,
	NotBefore	INT,
	NotAfter	INT,
	ExtUsage	INT,
	Hash	VARCHAR(256),
	DNTemplate	VARCHAR(256),
	PRIMARY KEY(NUM)
);


CREATE TABLE IF NOT EXISTS TB_CRL_PROFILE (
	Num	INT,
	Name	VARCHAR(256),
	Version	INT,
	LastUpdate	INT,
	NextUpdate	INT,
	Hash	VARCHAR(256),
	PRIMARY KEY(Num)
);

CREATE TABLE IF NOT EXISTS TB_SIGNER (
	Num	INT PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	Type	INT,
	DN	VARCHAR(256),
	DNHash	VARCHAR(256),
	Status	INT,
	Cert	Text,
	Info	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_USER (
	Num	INT PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	Name	VARCHAR(256),
	SSN	VARCHAR(256),
	EMAIL	VARCHAR(256),
	Status	INT,
	RefNum	VARCHAR(256),
	AuthCode	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_CERT (
	Num	INT PRIMARY KEY AUTO_INCREMENT,
	RegTime	INT,
	KeyNum	INT,
	UserNum	INT,
	signAlg	VARCHAR(256),
	Cert	Text,
	IsSelf	INT,
	IsCA	INT,
	IssuerNum	INT,
	SubjectDN	VARCHAR(256),
	Status	INT,
	Serial	VARCHAR(256),
	DNHash	VARCHAR(256),
	KeyHash	VARCHAR(256),
	CRLDP	VARCHAR(256)
);


CREATE TABLE IF NOT EXISTS TB_AUTH (
	Token	VARCHAR(256),
	UserName	VARCHAR(256),
	RegTime	INT,
	Valid	INT
);

CREATE TABLE IF NOT EXISTS TB_REVOKED (
	Seq	INT PRIMARY KEY AUTO_INCREMENT,
	CertNum	INT,
	IssuerNum	INT,
	Serial	VARCHAR(256),
	RevokedDate	INT,
	Reason	INT,
	CRLDP	VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS TB_CONFIG (
	Num	INT PRIMARY KEY AUTO_INCREMENT,
	Kind	INT,
	Name	VARCHAR(256),
	Value	VARCHAR(256)
);
