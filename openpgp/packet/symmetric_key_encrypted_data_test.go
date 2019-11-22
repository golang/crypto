package packet

// These test vectors contain V4 or V4 symmetric key encrypted packets followed
// by an integrity protected packet (either a SymmetricallyEncrypted (with MDC)
// or AEADEncrypted packet.

type packetSequence struct {
	password string
	packets  string
	contents string
}

var keyAndIpePackets = []*packetSequence{symEncTest, aeadEaxRFC, aeadOcbRFC}

var aeadEaxRFC = &packetSequence{
	password: "password",
	packets:  "c33e0507010308cd5a9f70fbe0bc6590bc669e34e500dcaedc5b32aa2dab02359dee19d07c3446c4312a34ae1967a2fb7e928ea5b4fa8012bd456d1738c63c36d44a0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476",
	contents: "cb1462000000000048656c6c6f2c20776f726c64210a",
}

var aeadOcbRFC = &packetSequence{
	password: "password",
	packets:  "c33d05070203089f0b7da3e5ea64779099e326e5400a90936cefb4e8eba08c6773716d1f2714540a38fcac529949dac529d3de31e15b4aeb729e330033dbedd4490107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098",
	contents: "cb1462000000000048656c6c6f2c20776f726c64210a",
}

var symEncTest = &packetSequence{
	password: "password",
	packets:  "c32e04090308f9f479ee0862ee8700a86d5cce4c166b5a7d664dcbe0f0eb2696a3e8a815fe8913251605ad79cc865f15d24301c3da8f5003383b9bd62c673589e2292d990902227311905ff4a7f694727578468e15d9f1aadb41572c4b2a789d7f93896661249200b64af9fbf6abf001f5498d036a",
	contents: "cb1875076d73672e7478745cafc23e636f6e74656e74732e0d0a",
}
