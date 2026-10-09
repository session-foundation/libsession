// This file contains a subset of TweetNaCl (https://tweetnacl.cr.yp.to/software.html) public domain
// code to perform the X25519 -> Ed25519 conversion; libsodium doesn't provide enough access to
// internals to compute this without hacking up libsodium's build, which is fragile.  Hence we use
// this subset of the portable TweetNaCl for that single function, and libsodium for everything
// else.

#include <array>
#include <cstdint>
#include <span>

#include "session/xed25519.hpp"

namespace session::xed25519 {

namespace {

    // clang-format off

#define FOR(i,n) for (i = 0;i < n;++i)

using gf = int64_t[16];

const gf gf1 = {1};

void car25519(gf o)
{
  int i;
  int64_t c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

void sel25519(gf p,gf q,int b)
{
  int64_t t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

void pack25519(uint8_t *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

void unpack25519(gf o, const uint8_t *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((int64_t)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

void A(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

void Z(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

void M(gf o,const gf a,const gf b)
{
  int64_t i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

void S(gf o,const gf a)
{
  M(o,a,a);
}

// Y
void inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

    // clang-format on

}  // namespace

std::array<unsigned char, 32> pubkey(std::span<const unsigned char, 32> x_pk) {
    gf u;
    unpack25519(u, x_pk.data());

    //  u - 1
    gf u_minus_one;
    Z(u_minus_one, u, gf1);

    // Compute: u + 1
    gf u_plus_one;
    A(u_plus_one, u, gf1);

    // Compute: (u + 1)^-1
    gf u_plus_one_inv;
    inv25519(u_plus_one_inv, u_plus_one);

    // Compute: y = (u - 1) * (u + 1)^-1
    gf y;
    M(y, u_minus_one, u_plus_one_inv);

    // Encode to 32 bytes (sign bit is naturally 0)
    std::array<unsigned char, 32> ed_pk;
    pack25519(ed_pk.data(), y);
    return ed_pk;
}

}  // namespace session::xed25519
