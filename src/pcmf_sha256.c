#include "pcmf_sha256.h"
#include <string.h>

/* FIPS 180-4 SHA-256. Minimal, dependency-free, well-defined behavior. */

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_compress(uint32_t st[8],const uint8_t block[64]){
    uint32_t w[64];
    for(int i=0;i<16;i++){
        w[i]=((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)
            |((uint32_t)block[i*4+2]<<8)|((uint32_t)block[i*4+3]);
    }
    for(int i=16;i<64;i++){
        uint32_t s0=ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for(int i=0;i<64;i++){
        uint32_t S1=ROTR(e,6)^ROTR(e,11)^ROTR(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+S1+ch+K[i]+w[i];
        uint32_t S0=ROTR(a,2)^ROTR(a,13)^ROTR(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

static const uint32_t INIT[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

/* Streamed core: state + 64-byte block carry. */
typedef struct { uint32_t st[8]; uint8_t buf[64]; size_t used; uint64_t total; } sha_ctx;

static void sha_init(sha_ctx *c){memcpy(c->st,INIT,sizeof INIT);c->used=0;c->total=0;}
static void sha_update(sha_ctx *c,const uint8_t *m,size_t len){
    c->total+=len;
    while(len>0){
        if(c->used==0&&len>=64){sha256_compress(c->st,m);m+=64;len-=64;continue;}
        size_t take=64-c->used; if(take>len)take=len;
        memcpy(c->buf+c->used,m,take);c->used+=take;m+=take;len-=take;
        if(c->used==64){sha256_compress(c->st,c->buf);c->used=0;}
    }
}
static void sha_final(sha_ctx *c,uint8_t out[32]){
    uint8_t tail[128];size_t tail_len=c->used;
    memcpy(tail,c->buf,tail_len);
    tail[tail_len++]=0x80;
    const size_t padded=(tail_len<=56)?64:128;
    memset(tail+tail_len,0,padded-tail_len);
    uint64_t bits=c->total*8ull;
    for(int i=0;i<8;i++)tail[padded-1-i]=(uint8_t)(bits>>(8*i));
    sha256_compress(c->st,tail);
    if(padded==128)sha256_compress(c->st,tail+64);
    for(int i=0;i<8;i++){
        out[i*4]  =(uint8_t)(c->st[i]>>24);out[i*4+1]=(uint8_t)(c->st[i]>>16);
        out[i*4+2]=(uint8_t)(c->st[i]>>8); out[i*4+3]=(uint8_t)c->st[i];
    }
}

void pcmf_sha256(const void *msg,size_t len,uint8_t out[32]){
    sha_ctx c;sha_init(&c);sha_update(&c,(const uint8_t*)msg,len);sha_final(&c,out);
}

void pcmf_hmac_sha256(const uint8_t *key,size_t key_len,
                      const void *msg,size_t len,uint8_t out[32]){
    uint8_t kblock[64],khash[32],ipad[64],opad[64];
    memset(kblock,0,sizeof kblock);
    if(key_len>64){
        pcmf_sha256(key,key_len,khash);
        memcpy(kblock,khash,32);
    }else if(key_len>0){
        memcpy(kblock,key,key_len);
    }
    for(int i=0;i<64;i++){ipad[i]=kblock[i]^0x36;opad[i]=kblock[i]^0x5c;}
    sha_ctx c;
    sha_init(&c);sha_update(&c,ipad,64);sha_update(&c,(const uint8_t*)msg,len);
    uint8_t inner[32];sha_final(&c,inner);
    sha_init(&c);sha_update(&c,opad,64);sha_update(&c,inner,32);
    sha_final(&c,out);
}

int pcmf_ct_equal(const void *a,const void *b,size_t n){
    const uint8_t *x=(const uint8_t*)a,*y=(const uint8_t*)b;
    volatile uint8_t diff=0;
    for(size_t i=0;i<n;i++)diff|=(uint8_t)(x[i]^y[i]);
    return diff==0;
}

void pcmf_to_hex(const uint8_t *in,size_t n,char *out){
    static const char hexd[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){out[i*2]=hexd[in[i]>>4];out[i*2+1]=hexd[in[i]&15];}
    out[n*2]='\0';
}

int pcmf_from_hex(const char *in,uint8_t *out,size_t n){
    if(strlen(in)!=n*2)return 0;
    for(size_t i=0;i<n;i++){
        char h=in[2*i],l=in[2*i+1];
        int hi=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:
               (h>='A'&&h<='F')?h-'A'+10:-1;
        int lo=(l>='0'&&l<='9')?l-'0':(l>='a'&&l<='f')?l-'a'+10:
               (l>='A'&&l<='F')?l-'A'+10:-1;
        if(hi<0||lo<0)return 0;
        out[i]=(uint8_t)((hi<<4)|lo);
    }
    return 1;
}
