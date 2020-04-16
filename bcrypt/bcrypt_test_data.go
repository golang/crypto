package bcrypt

// Passphrases contacto@martinugarte.com generated with dev/urandom entropy
// Bcrypt hashes computed with python's bcrypt https://pypi.org/project/bcrypt/

type InvalidHashTest struct {
	err  error
	hash []byte
}
var externalBcryptHashes = []struct {
	pass string
	salt string
	hash string
	cost int
}{
	{
		"",
		"JGZJSHED/woRIKSoTp5bZe",
		"$2b$12$JGZJSHED/woRIKSoTp5bZea/99GHy6jGK1ToltiTObaiRQMLxH3we",
		12,
	},
	{
		"allmine",
		"XajjQvNhvvRt5GSeFk1xFe",
		"$2a$10$XajjQuNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga",
		10,
	},
	{
		"pass",
		"GNk.4LiPcEcQxTb/FiWhfu",
		"$2b$12$GNk.4LiPcEcQxTb/FiWhfu52a11RA6Jh5r4mLpezmg6.DlYS3MKzy",
		12,
	},
	{
		"letmein",
		"biCUWeQbpfJiIT0hZJqOWO",
		"$2b$12$biCUWeQbpfJiIT0hZJqOWOQAPN93iU3MPDHkvsnKx3tqV2yWRtiNK",
		12,
	},
	{
		"010203040506070809",
		"60xRZwFvBNfExmNnV.twIO",
		"$2b$12$60xRZwFvBNfExmNnV.twIOgz89kFEpp83ruKh5bufkUWQvVikbfL2",
		12,
	},
	{
		"1.e4 e5 2. Nf3 Nc6 3. Bb4 Bb5",
		"9cgE2qZ1LbIKMPerEq/gIe",
		"$2b$12$9cgE2qZ1LbIKMPerEq/gIeTCKUHaB6v9QJmjmEY1A01lkT3hL3eb6",
		12,
	},
	{
		"!@#$%^&*()",
		"51NJndAjnyZOvS7YSH6rWe",
		"$2b$12$51NJndAjnyZOvS7YSH6rWesdaN02VMVMQnxv2b48Oe.pBxe1mFg6K",
		12,
	},
	{
		"LI\"}41SWG(SD@^:~td",
		"hakLP0gLwtpiA0LB.jgEP.",
		"$2b$12$hakLP0gLwtpiA0LB.jgEP.NCyuc8GkA.k943vBdX6qMJie5flQaJO",
		12,
	},
	{
		"VTaT^O<b%[8\\M7CJ&krtVTaT^O<b%[8\\M7CJ&krt",
		"o3Q7Grn/7RHqockRlJWave",
		"$2b$12$o3Q7Grn/7RHqockRlJWaveTMz1KcClmMaDR.KAnV3gPUlwcNsSfKq",
		12,
	},
	{
		"\"j%MgQ\"c{dRr07FDO{qo1j%MgQ\"c{dRr07FDO{qo1",
		"uG5.qLAVM6g9oFp6ucDAZe",
		"$2b$12$uG5.qLAVM6g9oFp6ucDAZe7QfjAz8qSFB8pFEximoK856UbnXCD.i",
		12,
	},
	{
		"HI`#ZWSY,wCXj>jIz(=-8AM[+\"L$${l(:]LBih&?)KHe*rLN$,z_g<]WWP1#Udh#\\gN+M9n*4",
		"qJAEBcCXXO5bF.O1iZhy9u",
		"$2b$12$qJAEBcCXXO5bF.O1iZhy9uEl35W84j9d1H6OAVfP19uR8hhS4QQzy",
		12,
	},
	// 57 byte password of old TestTooLongPasswordWord test. Notice that salt is repeated.
	{
		"012345678901234567890123456789012345678901234567890123456",
		"XajjQvNhvvRt5GSeFk1xFe",
		"$2a$10$XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C",
		10,
	},
}

// Generated with python's bcrypt
var randomSalts = []string {
	"Te0tzvXK54kCPxTib.Yrqe",
	"Sk24alQjTsdXwSlaUdUGNe",
	"CSzKaVGc70Z74Nbsu0lJje",
	"xXMqLl4/t21aJHlTcBN4h.",
	"GU.WqBHNelnEkg5ZfVDUR.",
	"qh0/aSSVJBx4cvMOtBsucO",
	"Oy5dSRPysuM6X/mVxuKmJO",
	"wuFoMgC2HEPHh87aifJOl.",
	"AiPCQjKBaVGaul9/XMp6Xe",
	"UdNZfjHo56pN9s7yawvWEu",
}

var invalidTests = []InvalidHashTest{
	{ErrHashTooShort, []byte("$2a$10$fooo")},
	{ErrHashTooShort, []byte("$2a")},
	{HashVersionTooNewError('3'), []byte("$3a$10$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")},
	{InvalidHashPrefixError('%'), []byte("%2a$10$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")},
	{InvalidCostError(32), []byte("$2a$32$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")},
}
