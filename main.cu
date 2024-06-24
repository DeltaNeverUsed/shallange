#include <stdio.h>
#include <cuda/std/bit>

__device__ constexpr unsigned int message_prefix_len = 16;

__device__ const uint32_t K[64] = { 
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
 };

__device__ uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

__device__ uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ uint32_t Sigma0(uint32_t x) {
    return cuda::std::rotr(x, 2) ^ cuda::std::rotr(x, 13) ^ cuda::std::rotr(x, 22);
}

__device__ uint32_t Sigma1(uint32_t x) {
    return cuda::std::rotr(x, 6) ^ cuda::std::rotr(x, 11) ^ cuda::std::rotr(x, 25);
}

__device__ uint32_t sigma0(uint32_t x) {
    return cuda::std::rotr(x, 7) ^ cuda::std::rotr(x, 18) ^ (x >> 3);
}

__device__ uint32_t sigma1(uint32_t x) {
    return cuda::std::rotr(x, 17) ^ cuda::std::rotr(x, 19) ^ (x >> 10);
}

__device__ void print_message(uint8_t *message) {
    for (size_t i = 0; i < 64; i++)
    {
        if (i%4 == 0)
            printf("\n");
        for (int y = 7; y >= 0; --y) {
            printf("%d", (message[(i/4) * 4 + (3 - i%4)] >> y) & 1);
        }
        printf(" ");
    }
    printf("\n");
}

__device__ __host__ void print_uint64(uint64_t value) {
    for (int i = 63; i >= 0; --i) {
        uint64_t mask = 1ULL << i;
        uint64_t bit = (value & mask) ? 1 : 0;

        if ((i + 1) % 8 == 0)
            printf(" ");
        if ((i + 1) % 32 == 0)
            printf("\n");
        printf("%d", bit);        
    }
    printf("\n");
}

__device__ __host__ void print_uint32(uint32_t value) {
    for (int i = 31; i >= 0; --i) {
        uint32_t mask = 1ULL << i;
        uint32_t bit = (value & mask) ? 1 : 0;

        if ((i + 1) % 8 == 0)
            printf(" ");
        printf("%d", bit);        
    }
    printf("\n");
}

__global__ void gpu_hash(uint32_t nonce_start) {
    union {
        char     bytes[64] = "DeltaNeverUsed/\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        uint32_t ints[16];
    } prefix;

    prefix.ints[15] = __byte_perm((message_prefix_len-1) * 8, 0, 0x0123);

    auto thread_id = threadIdx.x;
    auto block_id = blockIdx.x;
    auto global_id = thread_id + block_id * blockDim.x;

    union {
        uint8_t  message[512];
        uint32_t words[64];
    };


    //message[message_prefix_len-1] = 0x80;

    // maybe fix bit swappy swap
    for (size_t i = 0; i < 64; i+=4)
    {
        for (size_t l = 0; l < 4; l++)
        {
            auto index = i + 3 - l;
            message[i + l] = prefix.bytes[index];
        }

        //printf("%u\n", words[i/4]);
    }

    //message[62] = message_len_bits & 0xFF00;
    //message[63] = message_len_bits & 0x00FF;

    for (uint16_t i = 16; i < 64; i++)
    {
        auto womp = sigma1(words[i-2]) + words[i-7];
        auto wamp = sigma0(words[i-15]) + words[i-16];
        words[i] = womp + wamp;
        //printf("%u, %u\n", i, words[i]);
    }

    //print_message(message);

    
    print_message(message);
    print_message(message + 64);
    print_message(message + 64 * 2);
    print_message(message + 64 * 3);
    
   
    constexpr uint32_t h0[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint32_t ht[8];

    uint32_t a = 0x6a09e667;
    uint32_t b = 0xbb67ae85;
    uint32_t c = 0x3c6ef372;
    uint32_t d = 0xa54ff53a;
    uint32_t e = 0x510e527f;
    uint32_t f = 0x9b05688c;
    uint32_t g = 0x1f83d9ab;
    uint32_t h = 0x5be0cd19;
    
    for (size_t i = 0; i < 64; i++)
    {
        uint32_t t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + words[i];
        uint32_t t2 = Sigma0(a) + Maj(a,b,c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ht[0] = a + h0[0]; //__byte_perm(a + h0[0], 0, 0x0123);
    ht[1] = b + h0[1]; //__byte_perm(b + h0[1], 0, 0x0123);
    ht[2] = c + h0[2]; //__byte_perm(c + h0[2], 0, 0x0123);
    ht[3] = d + h0[3]; //__byte_perm(d + h0[3], 0, 0x0123);
    ht[4] = e + h0[4]; //__byte_perm(e + h0[4], 0, 0x0123);
    ht[5] = f + h0[5]; //__byte_perm(f + h0[5], 0, 0x0123);
    ht[6] = g + h0[6]; //__byte_perm(g + h0[6], 0, 0x0123);
    ht[7] = h + h0[7]; //__byte_perm(h + h0[7], 0, 0x0123);

    printf("%x%x%x%x%x%x%x%x", ht[0], ht[1], ht[2], ht[3], ht[4], ht[5], ht[6], ht[7]);

}


int main() {

    uint32_t nonce_start = 0;

    gpu_hash<<<1,1>>>(nonce_start);
}