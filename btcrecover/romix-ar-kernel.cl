/* romix-ar-kernel.cl -- OpenCL implementation of Armory KDF
 * Copyright (C) 2014, 2015 Christopher Gurnee
 *
 * This file is part of btcrecover.
 *
 * btcrecover is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * btcrecover is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/

 * If you find this program helpful, please consider a small
 * donation to the developer at the following Bitcoin address:
 *
 *           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
 *
 *                      Thank You!

 * This is pretty much ROMix-SHA512 as specified in the original scrypt
 * proposal at http://www.tarsnap.com/scrypt/scrypt.pdf (ROMix using SHA512 
 * as the hash function instead of the recommended BlockMix-Salsa20/8), 
 * however it includes a few deviations from "standard" ROMix to match
 * Armory's implementation. It also supports an optional space-time tradeoff
 * to permit larger global work sizes despite the high memory requirements.

 * The SHA512 portions of this code are attributed to the authors of the
 * JohnTheRipper software package, and in particular to Claudio André who 
 * developed the core OpenCL SHA512 functionality. It was pieced together 
 * from files downloaded from the JohnTheRipper source repository at the 
 * link below, and then lightly modified to suit the purposes of this 
 * software package, btcrecover. The original copyright notice attached
 * to the SHA512 code is below.

 * https://github.com/magnumripper/JohnTheRipper/tree/bleeding-jumbo/src/opencl
 
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */


// From opencl_device_info.h

//Copied from common-opencl.h
#define DEV_UNKNOWN                 0       //0
#define DEV_CPU                     (1 << 0)    //1
#define DEV_GPU                     (1 << 1)    //2
#define DEV_ACCELERATOR             (1 << 2)    //4
#define DEV_AMD                     (1 << 3)    //8
#define DEV_NVIDIA                  (1 << 4)    //16
#define DEV_INTEL                   (1 << 5)    //32
#define PLATFORM_APPLE              (1 << 6)    //64
#define DEV_AMD_GCN_10              (1 << 7)    //128
#define DEV_AMD_GCN_11              (1 << 8)    //256
#define DEV_AMD_GCN_12              (1 << 9)    //512
#define DEV_AMD_VLIW4               (1 << 12)   //4096
#define DEV_AMD_VLIW5               (1 << 13)   //8192
#define DEV_NV_C2X                  (1 << 14)   //16384
#define DEV_NV_C30                  (1 << 15)   //32768
#define DEV_NV_C32                  (1 << 16)   //65536
#define DEV_NV_C35                  (1 << 17)   //131072
#define DEV_NV_C5X                  (1 << 18)   //262144
#define DEV_USE_LOCAL               (1 << 20)   //1048576
#define DEV_NO_BYTE_ADDRESSABLE     (1 << 21)   //2097152
#define DEV_MESA                    (1 << 22)   //4M

#define cpu(n)                      ((n & DEV_CPU) == (DEV_CPU))
#define gpu(n)                      ((n & DEV_GPU) == (DEV_GPU))
#define gpu_amd(n)                  ((n & DEV_AMD) && gpu(n))
#define gpu_nvidia(n)               ((n & DEV_NVIDIA) && gpu(n))
#define gpu_intel(n)                ((n & DEV_INTEL) && gpu(n))
#define cpu_amd(n)                  ((n & DEV_AMD) && cpu(n))
#define cpu_intel(n)                ((n & DEV_INTEL) && cpu(n))
#define amd_gcn_10(n)               ((n & DEV_AMD_GCN_10) && gpu_amd(n))
#define amd_gcn_11(n)               ((n & DEV_AMD_GCN_11) && gpu_amd(n))
#define amd_gcn_12(n)               ((n & DEV_AMD_GCN_12) && gpu_amd(n))
#define amd_gcn(n)                  (amd_gcn_10(n) || (amd_gcn_11(n)) || amd_gcn_12(n))
#define amd_vliw4(n)                ((n & DEV_AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)                ((n & DEV_AMD_VLIW5) && gpu_amd(n))
#define nvidia_sm_2x(n)             ((n & DEV_NV_C2X) && gpu_nvidia(n))
#define nvidia_sm_3x(n)             (((n & DEV_NV_C30) || (n & DEV_NV_C32) || (n & DEV_NV_C35)) && gpu_nvidia(n))
#define nvidia_sm_5x(n)             ((n & DEV_NV_C5X) && gpu_nvidia(n))
#define no_byte_addressable(n)      ((n & DEV_NO_BYTE_ADDRESSABLE))
#define use_local(n)                ((n & DEV_USE_LOCAL))
#define platform_apple(p)           (get_platform_vendor_id(p) == PLATFORM_APPLE)

// From opencl_misc.h

/* Note: long is *always* 64-bit in OpenCL */
typedef uchar uint8_t;
typedef uint uint32_t;
typedef ulong uint64_t;

// TODO: I've no recent NVIDIA hardware to test this, so it's disabled on NVIDIA for safety
//#if !gpu_nvidia(DEVICE_INFO) || SM_MAJOR >= 5
#if !gpu_nvidia(DEVICE_INFO)
#define USE_BITSELECT 1
#endif

#if cpu(DEVICE_INFO)
#define HAVE_ANDNOT 1
#endif

// TODO: I've no recent NVIDIA hardware to test this, so it's disabled for safety
//#if SM_MAJOR >= 5 && (DEV_VER_MAJOR > 352 || (DEV_VER_MAJOR == 352 && DEV_VER_MINOR >= 21))
//#define HAVE_LUT3	1
//inline uint lut3(uint a, uint b, uint c, uint imm)
//{
//	uint r;
//	asm("lop3.b32 %0, %1, %2, %3, %4;"
//	    : "=r" (r)
//	    : "r" (a), "r" (b), "r" (c), "i" (imm));
//	return r;
//}
//#endif

#if USE_BITSELECT
#define SWAP64(n)	bitselect( \
		bitselect(rotate(n, 24UL), \
		          rotate(n, 8UL), 0x000000FF000000FFUL), \
		bitselect(rotate(n, 56UL), \
		          rotate(n, 40UL), 0x00FF000000FF0000UL), \
		0xFFFF0000FFFF0000UL)
#else
// You would not believe how many driver bugs variants of this macro reveal
#define SWAP64(n) \
            (((n)             << 56)   | (((n) & 0xff00)     << 40) |   \
            (((n) & 0xff0000) << 24)   | (((n) & 0xff000000) << 8)  |   \
            (((n) >> 8)  & 0xff000000) | (((n) >> 24) & 0xff0000)   |   \
            (((n) >> 40) & 0xff00)     | ((n)  >> 56))
#endif

// From opencl_sha2_common.h

//Macros.
#ifdef USE_BITSELECT
#define Ch(x, y, z)     bitselect(z, y, x)
#define Maj(x, y, z)    bitselect(x, y, z ^ x)
#else

#if HAVE_LUT3 && BITS_32
#define Ch(x, y, z) lut3(x, y, z, 0xca)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if HAVE_LUT3 && BITS_32
#define Maj(x, y, z) lut3(x, y, z, 0xe8)
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif
#endif

// From opencl_sha512.h

//Macros.
#if (cpu(DEVICE_INFO))
#define ror(x, n)             ((x >> n) | (x << (64UL-n)))
#else
#define ror(x, n)             (rotate(x, (64UL-n)))
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


// From sha512_kernel.cl

// Computes an SHA512 hash of a single 1024-bit block with a data length of 64 bytes
inline void sha512_len64(uint64_t* w)
{
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t;

    // Assumes input length was 64 bytes
    w[8] = 0x8000000000000000UL;  // The appended "1" bit
    #pragma unroll
    for (int i = 9; i < 15; i++)
        w[i] = 0;
    w[15] = 512;                  // The length in bits

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
	t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

	h = g;
	g = f;
	f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
	d = c;
	c = b;
	b = a;
	a = t;
    }

    #pragma unroll
    for (int i = 16; i < 80; i++) {
	w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
	t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

	h = g;
	g = f;
	f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
	d = c;
	c = b;
	b = a;
	a = t;
    }

    // Copy resulting SHA512 hash back into the input variable
    w[0] = a + H0;
    w[1] = b + H1;
    w[2] = c + H2;
    w[3] = d + H3;
    w[4] = e + H4;
    w[5] = f + H5;
    w[6] = g + H6;
    w[7] = h + H7;
}


// Not from JtR

// A 512-bit SHA512 hash result
typedef struct {
    ulong8 as_vector;
} hash_t;

// The Armory salt is 32 bytes long
typedef struct {
    ulong4 as_vector;
} salt_t;

// A 1024-bit SHA512 hash block
typedef union {
    uint64_t as_uint64[16];  // 1024 bits
    uint32_t as_uint32[32];  // 1024 bits
    hash_t   hash;           // 512 bits
    struct {
	uint64_t truncated_hash[4];  // 256 bits
	salt_t   salt;               // 256 bits
    };
} hash_block_t;

#define SWAP32(n)  (  ((n) << 24)          | (((n) & 0xff00) << 8) |  \
                     (((n) >> 8) & 0xff00) |  ((n) >> 24)  )


/* Implements the first half of ROMix: the lookup table (V) generation. This
 * generates an incremental portion of the table during each call starting at
 * V_start and calculating count entries. As a space-time tradeoff, it only
 * saves one out of every SAVE_EVERY table entries (SAVE_EVERY is a compile-time
 * constant, so the optimizer should remove the space-time code when it is
 * disabled by defining SAVE_EVERY=1).
 *
 * The V tables are split across four OpenCL buffers. OpenCL permits GPUs to
 * enforce a maximum buffer size of 1/4th the total available global memory,
 * so in order to use as much memory as possible we need four of them.
 */
__kernel
void kernel_fill_V(__global hash_t*  pV_buffer0,
		   __global hash_t*  pV_buffer1,
		   __global hash_t*  pV_buffer2,
		   __global hash_t*  pV_buffer3,
			    uint32_t V_start,
			    uint32_t count,
		   __global hash_t*  pX_buffer,
			    uint8_t  X_already_hashed)
{
    size_t global_id   = get_global_id(0);
    size_t global_size = get_global_size(0);

    // Store the address of this worker's ROMix lookup table in pV
    __global hash_t* pV;
    switch(global_id / (global_size / 4U)) {  // global_size % 4 is always 0
	case 0:
	    pV = pV_buffer0 + ((V_LEN-1) / SAVE_EVERY + 1) * global_id;
	    break;
	case 1:
	    pV = pV_buffer1 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/4U);
	    break;
	case 2:
	    pV = pV_buffer2 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/2U);
	    break;
	case 3:
	    pV = pV_buffer3 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/4U*3U);
    }

    // Get this worker's starting hash and copy it into the local working variable
    pX_buffer += global_id;
    hash_block_t X;
    X.hash = *pX_buffer;  // X is the running hash

    // Special case for the first hash which might already be done
    if (X_already_hashed) {
	// Just need to convert it's endianness
	#pragma unroll
	for (int i = 0; i < 8; i++)
	    X.as_uint64[i] = SWAP64(X.as_uint64[i]);
    } else {

	// Special case for the beginning of each iteration which needs
	// its hash truncated and the salt appended before it is hashed
	if (V_start == 0) {
	    // Convert endianness of the first 32 bytes
	    #pragma unroll
	    for (int i = 0; i < 4; i++)
		X.as_uint64[i] = SWAP64(X.as_uint64[i]);
	    // Overwrite the following 32 bytes with the salt
	    X.salt.as_vector = (ulong4)(SALT0,SALT1,SALT2,SALT3);
	} else {

	    // Convert endianness (of the entire 64-byte hash)
	    #pragma unroll
	    for (int i = 0; i < 8; i++)
		X.as_uint64[i] = SWAP64(X.as_uint64[i]);
	}

	sha512_len64(X.as_uint64);
    }

    if (V_start % SAVE_EVERY == 0)  // only save one out of every SAVE_EVERY in the lookup table
	pV[V_start / SAVE_EVERY] = X.hash;

    // Fill the rest of the lookup table
    count += V_start;
    for (uint32_t i = V_start + 1; i < count; i++) {

	sha512_len64(X.as_uint64);
	if (i % SAVE_EVERY == 0)  // only save one out of every SAVE_EVERY in the lookup table
	    pV[i / SAVE_EVERY] = X.hash;
    }

    // Convert endianness back and save X back to the I/O buffer
    #pragma unroll
    for (int i = 0; i < 8; i++)
	X.as_uint64[i] = SWAP64(X.as_uint64[i]);
    *pX_buffer = X.hash;
}


/* Implements the second half of ROMix: continuing hash iterations while mixing in
 * data based on table (V) lookups. This performs count of these iterations during
 * each call. Because only one out of every SAVE_EVERY table entries were saved,
 * unsaved entries must be lazily generated based on the prior saved entry.
 */
__kernel
void kernel_lookup_V(__global hash_t*  pV_buffer0,
		     __global hash_t*  pV_buffer1,
		     __global hash_t*  pV_buffer2,
		     __global hash_t*  pV_buffer3,
			      uint32_t count,
		     __global hash_t*  pX_buffer)
{
    size_t global_id   = get_global_id(0);
    size_t global_size = get_global_size(0);

    // Store the address of this worker's ROMix lookup table in pV
    __global hash_t* pV;
    switch(global_id / (global_size / 4U)) {  // global_size % 4 is always 0
	case 0:
	    pV = pV_buffer0 + ((V_LEN-1) / SAVE_EVERY + 1) * global_id;
	    break;
	case 1:
	    pV = pV_buffer1 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/4U);
	    break;
	case 2:
	    pV = pV_buffer2 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/2U);
	    break;
	case 3:
	    pV = pV_buffer3 + ((V_LEN-1) / SAVE_EVERY + 1) * (global_id - global_size/4U*3U);
    }

    // Get this worker's starting hash and copy it into the local working variable
    hash_block_t X;
    pX_buffer += global_id;
    X.hash = *pX_buffer;  // X is the running hash

    // Convert endianness
    #pragma unroll
    for (int i = 0; i < 8; i++)
	X.as_uint64[i] = SWAP64(X.as_uint64[i]);

    uint32_t j, mod;

    hash_block_t Vj;  // Vj will be the j'th saved hash in the lookup table (V)

    // Do the lookups and continuing hash iterations
    for (uint32_t i = 0; i < count; i++) {

	// This is how Armory implements Integerify to calculate the lookup index
	// (note its endianness is swapped when compared to the Armory source code)
	j = SWAP32(X.as_uint32[14]) % V_LEN;

	Vj.hash = pV[j / SAVE_EVERY];

	// If the desired lookup index wasn't in the table, calculate it
	mod = j % SAVE_EVERY;
	for (uint32_t n = 0; n < mod; n++)
	    sha512_len64(Vj.as_uint64);

	// Calculate the next hash
	X.hash.as_vector ^= Vj.hash.as_vector;
	sha512_len64(X.as_uint64);
    }

    // Convert endianness back and save X back to the I/O buffer
    #pragma unroll
    for (int i = 0; i < 8; i++)
	X.as_uint64[i] = SWAP64(X.as_uint64[i]);
    *pX_buffer = X.hash;
}
