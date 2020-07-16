BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "TB_REQ" (
	"SEQ"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"REGTIME"	INTEGER,
	"KEY_NUM"	INTEGER,
	"NAME"	TEXT,
	"DN"	TEXT,
	"CSR"	TEXT,
	"HASH"	TEXT,
	"Status"	INTEGER
);
CREATE TABLE IF NOT EXISTS "TB_KEY_PAIR" (
	"NUM"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"ALGORITHM"	TEXT,
	"NAME"	Text,
	"PUBLIC"	Text,
	"PRIVATE"	Text,
	"PARAM"	Text,
	"Status"	INTEGER
);
CREATE TABLE IF NOT EXISTS "TB_AUDIT" (
	"Seq"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"Kind"	INTEGER,
	"Operation"	INTEGER,
	"UserName"	TEXT,
	"Info"	TEXT,
	"MAC"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_KMS" (
	"SEQ"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	"REGTIME"	INTEGER,
	"STATUS"	INTEGER,
	"TYPE"	INTEGER,
	"ID"	TEXT,
	"INFO"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_CERT_POLICY" (
	"NUM"	INTEGER,
	"Name"	TEXT,
	"Version"	INTEGER,
	"NotBefore"	INTEGER,
	"NotAfter"	INTEGER,
	"Hash"	TEXT,
	"DNTemplate"	TEXT,
	PRIMARY KEY("NUM")
);
CREATE TABLE IF NOT EXISTS "TB_CRL" (
	"Num"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"IssuerNum"	INTEGER,
	"signAlg"	TEXT,
	"CRLDP"	TEXT,
	"CRL"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_CRL_POLICY" (
	"Num"	INTEGER,
	"Name"	TEXT,
	"Version"	INTEGER,
	"LastUpdate"	INTEGER,
	"NextUpdate"	INTEGER,
	"Hash"	TEXT,
	PRIMARY KEY("Num")
);
CREATE TABLE IF NOT EXISTS "TB_SIGNER" (
	"Num"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"Type"	INTEGER,
	"DN"	TEXT,
	"DNHash"	TEXT,
	"Status"	INTEGER,
	"Cert"	TEXT,
	"Desc"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_USER" (
	"Num"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"Name"	TEXT,
	"SSN"	TEXT,
	"EMAIL"	TEXT,
	"Status"	INTEGER,
	"RefNum"	TEXT,
	"AuthCode"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_CERT" (
	"Num"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"RegTime"	INTEGER,
	"KeyNum"	INTEGER,
	"UserNum"	INTEGER,
	"signAlg"	TEXT,
	"Cert"	TEXT,
	"IsSelf"	INTEGER,
	"IsCA"	INTEGER,
	"IssuerNum"	INTEGER,
	"SubjectDN"	TEXT,
	"Status"	INTEGER,
	"Serial"	TEXT,
	"DNHash"	TEXT,
	"KeyHash"	TEXT,
	"CRLDP"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_AUTH" (
	"Token"	TEXT,
	"UserName"	TEXT,
	"RegTime"	INTEGER,
	"Valid"	INTEGER
);
CREATE TABLE IF NOT EXISTS "TB_REVOKED" (
	"Seq"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"CertNum"	INTEGER,
	"IssuerNum"	INTEGER,
	"Serial"	TEXT,
	"RevokedDate"	INTEGER,
	"Reason"	INTEGER,
	"CRLDP"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_ADMIN" (
	"Seq"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"Name"	TEXT,
	"Password"	TEXT,
	"Status"	INTEGER,
	"Email"	TEXT,
	"Type"	INTEGER
);
CREATE TABLE IF NOT EXISTS "TB_CONFIG" (
	"Num"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"Kind"	INTEGER,
	"Name"	TEXT,
	"Value"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_CRL_POLICY_EXTENSION" (
	"Seq"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"PolicyNum"	INTEGER,
	"Critical"	INTEGER,
	"SN"	TEXT,
	"Value"	TEXT
);
CREATE TABLE IF NOT EXISTS "TB_CERT_POLICY_EXTENSION" (
	"Seq"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"PolicyNum"	INTEGER,
	"Critical"	INTEGER,
	"SN"	TEXT,
	"Value"	TEXT
);
COMMIT;
