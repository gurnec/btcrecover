/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

/*
 * This software is originally attributed to the authors of the JohnTheRipper
 * software package, and in particular to Claudio André who developed all of
 * the core SHA512 functionality. It was pieced together from files downloaded
 * from the JohnTheRipper source repository at the link below, and then
 * lightly modified to suit the purposes of this software package, btcrecover.
 *
 * https://github.com/magnumripper/JohnTheRipper/tree/bleeding-jumbo/src/opencl
 */

#define _OPENCL_COMPILER


// From opencl_device_info.h

// Copied from common-opencl.h
#define DEV_UNKNOWN                 0
#define DEV_CPU                     1
#define DEV_GPU                     2
#define DEV_ACCELERATOR             4
#define DEV_AMD                     64
#define DEV_NVIDIA                  128
#define DEV_INTEL                   256
#define PLATFORM_APPLE              512
#define DEV_AMD_GCN                 1024
#define DEV_AMD_VLIW4               2048
#define DEV_AMD_VLIW5               4096
#define DEV_NO_BYTE_ADDRESSABLE     8192
#define DEV_USE_LOCAL               32768

#define cpu(n)                      ((n & DEV_CPU) == (DEV_CPU))
#define gpu(n)                      ((n & DEV_GPU) == (DEV_GPU))
#define gpu_amd(n)                  ((n & DEV_AMD) && gpu(n))
#define gpu_nvidia(n)               ((n & DEV_NVIDIA) && gpu(n))
#define gpu_intel(n)                ((n & DEV_INTEL) && gpu(n))
#define cpu_amd(n)                  ((n & DEV_AMD) && cpu(n))
#define amd_gcn(n)                  ((n & DEV_AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)                ((n & DEV_AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)                ((n & DEV_AMD_VLIW5) && gpu_amd(n))
#define no_byte_addressable(n)      ((n & DEV_NO_BYTE_ADDRESSABLE))
#define use_local(n)                ((n & DEV_USE_LOCAL))
#define platform_apple(p)           (get_platform_vendor_id(p) == PLATFORM_APPLE)


// From opencl_sha2_common.h

// Type names definition.
// NOTE: long is always 64-bit in OpenCL, and long long is 128 bit.
#ifdef _OPENCL_COMPILER
	#define uint8_t  unsigned char
	#define uint16_t unsigned short
	#define uint32_t unsigned int
	#define uint64_t unsigned long
#endif

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#else
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[(index)] = (val)
#endif

#ifdef _OPENCL_COMPILER
#if no_byte_addressable(DEVICE_INFO)
    #define PUT         PUTCHAR
    #define BUFFER      ctx->buffer->mem_32
#else
    #define PUT         ATTRIB
    #define BUFFER      ctx->buffer->mem_08
#endif
#endif


// From opencl_sha512.h

// Macros
#define SWAP(n) \
            (((n)             << 56)   | (((n) & 0xff00)     << 40) |   \
            (((n) & 0xff0000) << 24)   | (((n) & 0xff000000) << 8)  |   \
            (((n) >> 8)  & 0xff000000) | (((n) >> 24) & 0xff0000)   |   \
            (((n) >> 40) & 0xff00)     | ((n)  >> 56))

#if gpu_amd(DEVICE_INFO)
        #define Ch(x,y,z)       bitselect(z, y, x)
        #define Maj(x,y,z)      bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (64UL-n))
        #define SWAP64(n)       (as_ulong(as_uchar8(n).s76543210))
#else
        #define Ch(x,y,z)       ((x & y) ^ ( (~x) & z))
        #define Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (64-n)))
        #define SWAP64(n)       SWAP(n)
#endif
#define Sigma0(x)               ((ror(x,28UL)) ^ (ror(x,34UL)) ^ (ror(x,39UL)))
#define Sigma1(x)               ((ror(x,14UL)) ^ (ror(x,18UL)) ^ (ror(x,41UL)))
#define sigma0(x)               ((ror(x,1UL))  ^ (ror(x,8UL))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19UL)) ^ (ror(x,61UL)) ^ (x>>6))

// SHA512 constants
#define H0      0x6a09e667f3bcc908UL
#define H1      0xbb67ae8584caa73bUL
#define H2      0x3c6ef372fe94f82bUL
#define H3      0xa54ff53a5f1d36f1UL
#define H4      0x510e527fade682d1UL
#define H5      0x9b05688c2b3e6c1fUL
#define H6      0x1f83d9abfb41bd6bUL
#define H7      0x5be0cd19137e2179UL

#ifdef _OPENCL_COMPILER
__constant uint64_t k[] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

__constant uint64_t clear_mask[] = {
    0xffffffffffffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, //0
    0x00000000000000ffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,
    0x000000000000ffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, //16
    0x0000000000ffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,
    0x00000000ffffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, //32
    0x000000ffffffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,
    0x0000ffffffffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, //48
    0x00ffffffffffffffUL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL, 0x0UL,
    0xffffffffffffffffUL                                                   //64
};

#define CLEAR_BUFFER_64_FAST(dest, start) {        \
    uint32_t tmp, pos;                             \
    tmp = (uint32_t) ((start & 7) << 3);           \
    pos = (uint32_t) (start >> 3);                 \
    dest[pos] = dest[pos] & clear_mask[tmp];       \
}

#endif


// From opencl_rawsha512-ng.h

// Data types
typedef union {
    uint8_t                     mem_08[8];
    uint16_t                    mem_16[4];
    uint32_t                    mem_32[2];
    uint64_t                    mem_64[1];
} buffer_64;

typedef struct {
    uint64_t                    H[8];           //512 bits
    uint32_t                    buflen;
    buffer_64                   buffer[16];     //1024bits
} sha512_ctx;


// From sha512-ng_kernel.cl

inline void sha512_block(sha512_ctx * ctx, uint32_t iterations) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    uint64_t w[16], w8;

    // Copy input arg into local input variable and convert endianness
    #pragma unroll
    for (int i = 0; i < 8; i++)
	w[i] = SWAP64(ctx->buffer[i].mem_64[0]);

    // Has been set correctly by finish_ctx()
    w[8] = w8 = SWAP64(ctx->buffer[8].mem_64[0]);  // The appended 1
    w[15] = ctx->buffer[15].mem_64[0];             // The length

    // Assumes length is 64 bytes
    #pragma unroll
    for (int i = 9; i < 15; i++)
	w[i] = 0;

    // Do a complete SHA512 hash for each requested iteration
    for (size_t iter_count = 0; iter_count < iterations; iter_count++) {

	a = H0;
	b = H1;
	c = H2;
	d = H3;
	e = H4;
	f = H5;
	g = H6;
	h = H7;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
	    t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
	    t2 = Maj(a, b, c) + Sigma0(a);

	    h = g;
	    g = f;
	    f = e;
	    e = d + t1;
	    d = c;
	    c = b;
	    b = a;
	    a = t1 + t2;
	}

	#pragma unroll
	for (int i = 16; i < 80; i++) {
	    w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
	    t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
	    t2 = Maj(a, b, c) + Sigma0(a);

	    h = g;
	    g = f;
	    f = e;
	    e = d + t1;
	    d = c;
	    c = b;
	    b = a;
	    a = t1 + t2;
	}

	// Copy resulting SHA512 hash into the local input variable
	w[0] = a + H0;
	w[1] = b + H1;
	w[2] = c + H2;
	w[3] = d + H3;
	w[4] = e + H4;
	w[5] = f + H5;
	w[6] = g + H6;
	w[7] = h + H7;

	// Assumes original input length was 64 bytes
	w[8] = w8;                          // The appended 1
	for (int i = 9; i < 15; i++)
	    w[i] = 0;
	w[15] = ctx->buffer[15].mem_64[0];  // The length
    }

    // Copy resulting SHA512 hash into the output arg and convert endianness
    #pragma unroll
    for (int i = 0; i < 8; i++)
	ctx->H[i] = SWAP64(w[i]);
}

inline void ctx_append_1(sha512_ctx * ctx) {

    PUT(BUFFER, ctx->buflen, 0x80);

    CLEAR_BUFFER_64_FAST(ctx->buffer->mem_64, ctx->buflen + 1);
}

inline void ctx_add_length(sha512_ctx * ctx) {

    ctx->buffer[15].mem_64[0] = (uint64_t) (ctx->buflen * 8);
}

inline void finish_ctx(sha512_ctx * ctx) {

    ctx_append_1(ctx);
    ctx_add_length(ctx);
}

inline void sha512_crypt(sha512_ctx * ctx, uint32_t iterations) {

    finish_ctx(ctx);

    /* Run the collected hash value through SHA512. */
    sha512_block(ctx, iterations);
}

__kernel
void kernel_sha512_bc(__global uint32_t* hashes_buffer,
		               uint32_t  iterations)
{
    sha512_ctx ctx;

    // Get location of the hash to work on for this kernel
    hashes_buffer += (get_global_id(0) << 4);

    // Copy the initial hash from the I/O buffer into ctx
    #pragma unroll
    for (uint32_t i = 0; i < 16; i++)
	ctx.buffer->mem_32[i] = hashes_buffer[i];
    ctx.buflen = 64;

    // Perform SHA512 iterations
    sha512_crypt(&ctx, iterations);

    // Copy the result back into the I/O buffer
    #pragma unroll
    for (uint32_t i = 0; i < 16; i++)
	hashes_buffer[i] = ((uint32_t*)ctx.H)[i];
}
