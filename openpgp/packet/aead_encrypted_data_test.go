package packet

// RFC4880bis, sec. A.3.4.

// Includes both EAX and OCB samples
var samplesAeadEncryptedDataPacket = []struct {
	mode, cek, adata, nonce, plaintext, ciphertext, tag, finalTag, full string
	chunkSize                                                           uint8
}{
	{"eax",
		"86f1efb86952329f24acd3bfd0e5346d",
		"d40107010e0000000000000000",
		"b732379f73c4928de25facfe6517ec10",
		"cb1462000000000048656c6c6f2c20776f726c64210a",
		"5dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8",
		"dbcb49862655dea88d06a81486801b0f",
		"f387bd2eab013de1259586906eab2476",
		`d44a0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476`,
		14},
	{"ocb",
		"d1f01ba30e130aa7d2582c16e050ae44",
		"d40107020e0000000000000000",
		"5ed2bc1e470abe8f1d644c7a6c8a56",
		"cb1462000000000048656c6c6f2c20776f726c64210a",
		"7b0f7701196611a154ba9c2574cd056284a8ef68035c",
		"623d93cc708a43211bb6eaf2b27f7c18",
		"d571bcd83b20add3a08b73af15b9a098",
		`d4490107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098`,
		14},
}
