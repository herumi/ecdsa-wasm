#define PUT(x) std::cout << #x "=" << (x) << std::endl;
#include <stdlib.h>
#include <stdio.h>
void put(const void *buf, size_t bufSize)
{
	const unsigned char* p = (const unsigned char*)buf;
	for (size_t i = 0; i < bufSize; i++) {
		printf("%02x", p[i]);
	}
	printf("\n");
}
#include <mcl/ecdsa.hpp>
#include <cybozu/test.hpp>
#include <cybozu/benchmark.hpp>

using namespace mcl::ecdsa;

CYBOZU_TEST_AUTO(ecdsa)
{
	init();
	SecretKey sec;
	PublicKey pub;
	sec.setByCSPRNG();
	getPublicKey(pub, sec);
	Signature sig;
	const std::string msg = "hello";
	sign(sig, sec, msg.c_str(), msg.size());
	CYBOZU_TEST_ASSERT(verify(sig, pub, msg.c_str(), msg.size()));
	sig.s += 1;
	CYBOZU_TEST_ASSERT(!verify(sig, pub, msg.c_str(), msg.size()));
}

void serializeStrTest(const std::string& msg, const std::string& secHex, const std::string& pubHex, const std::string& sigHex)
{
	// old serialization
	setSeriailzeMode(SerializeOld);
	SecretKey sec;
	sec.setStr(secHex, 16);
	CYBOZU_TEST_EQUAL(sec.getStr(16), secHex);
	PublicKey pub;
	getPublicKey(pub, sec);
	pub.normalize();
	const std::string xHex = pubHex.substr(0, 64);
	const std::string yHex = pubHex.substr(64, 64);
	Ec t(Fp(xHex, 16), Fp(yHex, 16));
	CYBOZU_TEST_EQUAL(pub, t);
	Signature sig;
	const std::string rHex = sigHex.substr(0, 64);
	const std::string sHex = sigHex.substr(64, 64);
	sig.r.setStr(rHex, 16);
	sig.s.setStr(sHex, 16);
	normalizeSignature(sig);
	CYBOZU_TEST_ASSERT(verify(sig, pub, msg.c_str(), msg.size()));
	// recover mode
	setSeriailzeMode(SerializeBitcoin);
}

void serializeBinaryTest(const std::string& msg, const std::string& secHex, const std::string& pubHex, const std::string& sigHex)
{
	// old serialization
	setSeriailzeMode(SerializeOld);

	SecretKey sec;
	sec.deserializeHexStr(secHex);
	CYBOZU_TEST_EQUAL(sec.serializeToHexStr(), secHex);
	PublicKey pub;
	getPublicKey(pub, sec);
	pub.normalize();
#if 0
	Ec t;
	t.deserializeHexStr(pubHex);
#else
	const std::string xHex = pubHex.substr(0, 64);
	const std::string yHex = pubHex.substr(64, 64);
	Ec t;
	t.x.deserializeHexStr(xHex);
	t.y.deserializeHexStr(yHex);
	t.z = 1;
#endif
	CYBOZU_TEST_EQUAL(pub, t);
	Signature sig;
	sig.deserializeHexStr(sigHex);
	normalizeSignature(sig);
	CYBOZU_TEST_ASSERT(verify(sig, pub, msg.c_str(), msg.size()));
	// recover mode
std::cout << std::hex;
	setSeriailzeMode(SerializeBitcoin);
	char buf[100];
	size_t n = sig.serialize(buf, sizeof(buf));
	CYBOZU_TEST_ASSERT(n > 0);
	Signature sig2;
	CYBOZU_TEST_EQUAL(sig2.deserialize(buf, n), n);
	CYBOZU_TEST_EQUAL(sig.r, sig2.r);
	CYBOZU_TEST_EQUAL(sig.s, sig2.s);
}

CYBOZU_TEST_AUTO(value)
{
	const struct Tbl {
		const char *msg;
		const char *sec;
		const char *pub;
		const char *sig;
	} tbl[] = {
		{
			"hello",
			"83ecb3984a4f9ff03e84d5f9c0d7f888a81833643047acc58eb6431e01d9bac8",
			"653bd02ba1367e5d4cd695b6f857d1cd90d4d8d42bc155d85377b7d2d0ed2e7104e8f5da403ab78decec1f19e2396739ea544e2b14159beb5091b30b418b813a",
			"a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5de5d79a2ba44e311d04fdca263639283965780bce9169822be9cc81756e95a24"
		},
		// generated data from Python:ecdsa with ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
		{
			"hello",
			"b1aa6282b14e5ffbf6d12f783612f804e6a20d1a9734ffbb6c9923c670ee8da2",
			"0a09ff142d94bc3f56c5c81b75ea3b06b082c5263fbb5bd88c619fc6393dda3da53e0e930892cdb7799eea8fd45b9fff377d838f4106454289ae8a080b111f8d",
			"50839a97404c24ec39455b996e4888477fd61bcf0ffb960c7ffa3bef104501919671b8315bb5c1611d422d49cbbe7e80c6b463215bfad1c16ca73172155bf31a"
		},
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		serializeStrTest(tbl[i].msg, tbl[i].sec, tbl[i].pub, tbl[i].sig);
		serializeBinaryTest(tbl[i].msg, tbl[i].sec, tbl[i].pub, tbl[i].sig);
	}
}

CYBOZU_TEST_AUTO(serializeDer)
{
	const char *r ="ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f";
	const char *s = "7a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed";
	Signature sig;
	sig.r.setStr(r, 16);
	sig.s.setStr(s, 16);
	const uint8_t expected[] = {0x30, 0x45, 0x02, 0x21, 0x00, 0xed, 0x81, 0xff, 0x19, 0x2e, 0x75, 0xa3, 0xfd, 0x23, 0x04, 0x00, 0x4d, 0xca, 0xdb, 0x74, 0x6f, 0xa5, 0xe2, 0x4c, 0x50, 0x31, 0xcc, 0xfc, 0xf2, 0x13, 0x20, 0xb0, 0x27, 0x74, 0x57, 0xc9, 0x8f, 0x02, 0x20, 0x7a, 0x98, 0x6d, 0x95, 0x5c, 0x6e, 0x0c, 0xb3, 0x5d, 0x44, 0x6a, 0x89, 0xd3, 0xf5, 0x61, 0x00, 0xf4, 0xd7, 0xf6, 0x78, 0x01, 0xc3, 0x19, 0x67, 0x74, 0x3a, 0x9c, 0x8e, 0x10, 0x61, 0x5b, 0xed};
	uint8_t buf[100];
	size_t n = sig.serialize(buf, sizeof(buf));
	CYBOZU_TEST_EQUAL(n, sizeof(expected));
	CYBOZU_TEST_EQUAL_ARRAY(buf, expected, n);
	Signature sig2;
	CYBOZU_TEST_EQUAL(n, sig2.deserialize(buf, n));
	CYBOZU_TEST_EQUAL(sig.r, sig2.r);
	CYBOZU_TEST_EQUAL(sig.s, sig2.s);
}

CYBOZU_TEST_AUTO(bench)
{
	const std::string msg = "hello";
	SecretKey sec;
	PublicKey pub;
	PrecomputedPublicKey ppub;
	sec.setByCSPRNG();
	getPublicKey(pub, sec);
	ppub.init(pub);
	Signature sig;
	CYBOZU_BENCH_C("sign", 1000, sign, sig, sec, msg.c_str(), msg.size());
	CYBOZU_BENCH_C("pub.verify ", 1000, verify, sig, pub, msg.c_str(), msg.size());
	CYBOZU_BENCH_C("ppub.verify", 1000, verify, sig, ppub, msg.c_str(), msg.size());
}
