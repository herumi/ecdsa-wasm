#pragma once
/**
	@file
	@brief ECDSA
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <mcl/fp.hpp>
#include <mcl/ec.hpp>
#include <mcl/ecparam.hpp>
#include <mcl/window_method.hpp>

namespace mcl { namespace ecdsa {

namespace local {

#ifndef MCLSHE_WIN_SIZE
	#define MCLSHE_WIN_SIZE 10
#endif
static const size_t winSize = MCLSHE_WIN_SIZE;

struct FpTag;
struct ZnTag;

} // mcl::ecdsa::local

typedef mcl::FpT<local::FpTag, 256> Fp;
typedef mcl::FpT<local::ZnTag, 256> Zn;
typedef mcl::EcT<Fp> Ec;

namespace local {

struct Param {
	Ec P;
	mcl::fp::WindowMethod<Ec> Pbase;
	size_t bitSize;
};

inline Param& getParam()
{
	static Param p;
	return p;
}

/*
	y = x mod n
*/
inline void FpToZn(Zn& y, const Fp& x)
{
	fp::Block b;
	x.getBlock(b);
	bool ret;
	y.setArrayMod(&ret, b.p, b.n);
	assert(ret);
	(void)ret;
}

inline void setHashOf(Zn& x, const void *msg, size_t msgSize)
{
	const size_t mdSize = 32;
	uint8_t md[mdSize];
	mcl::fp::sha256(md, mdSize, msg, msgSize);
	bool b;
	x.setBigEndianMod(&b, md, mdSize);
	assert(b);
	(void)b;
}

} // mcl::ecdsa::local

const local::Param& param = local::getParam();

inline void init(bool *pb)
{
	local::Param& p = local::getParam();
	mcl::initCurve<Ec, Zn>(pb, MCL_SECP256K1, &p.P);
	if (!*pb) return;
	p.bitSize = 256;
	p.Pbase.init(pb, p.P, p.bitSize, local::winSize);
	// isValid() checks the order
	Ec::setOrder(Zn::getOp().mp);
	Fp::setETHserialization(true);
	Zn::setETHserialization(true);
	Ec::setIoMode(mcl::IoEcAffineSerialize);
}

#ifndef CYBOZU_DONT_USE_EXCEPTION
inline void init()
{
	bool b;
	init(&b);
	if (!b) throw cybozu::Exception("ecdsa:init");
}
#endif

typedef Zn SecretKey;
typedef Ec PublicKey;

struct PrecomputedPublicKey {
	mcl::fp::WindowMethod<Ec> pubBase_;
	void init(bool *pb, const PublicKey& pub)
	{
		pubBase_.init(pb, pub, param.bitSize, local::winSize);
	}
#ifndef CYBOZU_DONT_USE_EXCEPTION
	void init(const PublicKey& pub)
	{
		bool b;
		init(&b, pub);
		if (!b) throw cybozu::Exception("ecdsa:PrecomputedPublicKey:init");
	}
#endif
};

inline void getPublicKey(PublicKey& pub, const SecretKey& sec)
{
	Ec::mul(pub, param.P, sec);
	pub.normalize();
}

struct Signature : public mcl::fp::Serializable<Signature> {
	Zn r, s;
	template<class InputStream>
	void load(bool *pb, InputStream& is, int ioMode = IoSerialize)
	{
		r.load(pb, is, ioMode); if (!*pb) return;
		s.load(pb, is, ioMode);
	}
	template<class OutputStream>
	void save(bool *pb, OutputStream& os, int ioMode = IoSerialize) const
	{
		const char sep = *fp::getIoSeparator(ioMode);
		r.save(pb, os, ioMode); if (!*pb) return;
		if (sep) {
			cybozu::writeChar(pb, os, sep);
			if (!*pb) return;
		}
		s.save(pb, os, ioMode);
	}
#ifndef CYBOZU_DONT_USE_EXCEPTION
	template<class InputStream>
	void load(InputStream& is, int ioMode = IoSerialize)
	{
		bool b;
		load(&b, is, ioMode);
		if (!b) throw cybozu::Exception("ecdsa:Signature:load");
	}
	template<class OutputStream>
	void save(OutputStream& os, int ioMode = IoSerialize) const
	{
		bool b;
		save(&b, os, ioMode);
		if (!b) throw cybozu::Exception("ecdsa:Signature:save");
	}
#endif
#ifndef CYBOZU_DONT_USE_STRING
	friend std::istream& operator>>(std::istream& is, Signature& self)
	{
		self.load(is, fp::detectIoMode(Ec::getIoMode(), is));
		return is;
	}
	friend std::ostream& operator<<(std::ostream& os, const Signature& self)
	{
		self.save(os, fp::detectIoMode(Ec::getIoMode(), os));
		return os;
	}
#endif
};

inline void sign(Signature& sig, const SecretKey& sec, const void *msg, size_t msgSize)
{
	Zn& r = sig.r;
	Zn& s = sig.s;
	Zn z, k;
	local::setHashOf(z, msg, msgSize);
	Ec Q;
	for (;;) {
		bool b;
		k.setByCSPRNG(&b);
		(void)b;
		param.Pbase.mul(Q, k);
		if (Q.isZero()) continue;
		Q.normalize();
		local::FpToZn(r, Q.x);
		if (r.isZero()) continue;
		Zn::mul(s, r, sec);
		s += z;
		if (s.isZero()) continue;
		s /= k;
		return;
	}
}

namespace local {

inline void mulDispatch(Ec& Q, const PublicKey& pub, const Zn& y)
{
	Ec::mul(Q, pub, y);
}

inline void mulDispatch(Ec& Q, const PrecomputedPublicKey& ppub, const Zn& y)
{
	ppub.pubBase_.mul(Q, y);
}

template<class Pub>
inline bool verify(const Signature& sig, const Pub& pub, const void *msg, size_t msgSize)
{
	const Zn& r = sig.r;
	const Zn& s = sig.s;
	if (r.isZero() || s.isZero()) return false;
	Zn z, w, u1, u2;
	local::setHashOf(z, msg, msgSize);
	Zn::inv(w, s);
	Zn::mul(u1, z, w);
	Zn::mul(u2, r, w);
	Ec Q1, Q2;
	param.Pbase.mul(Q1, u1);
//	Ec::mul(Q2, pub, u2);
	local::mulDispatch(Q2, pub, u2);
	Q1 += Q2;
	if (Q1.isZero()) return false;
	Q1.normalize();
	Zn x;
	local::FpToZn(x, Q1.x);
	return r == x;
}

} // mcl::ecdsa::local

inline bool verify(const Signature& sig, const PublicKey& pub, const void *msg, size_t msgSize)
{
	return local::verify(sig, pub, msg, msgSize);
}

inline bool verify(const Signature& sig, const PrecomputedPublicKey& ppub, const void *msg, size_t msgSize)
{
	return local::verify(sig, ppub, msg, msgSize);
}

} } // mcl::ecdsa

