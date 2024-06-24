#include <stdio.h>
#include <cuda/std/bit>
#include <chrono>

__device__ constexpr uint64_t hashes_per_thread = 0x100000;
__device__ constexpr char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

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

__device__ __host__ bool is_hash_smaller(const uint32_t* hash1, const uint32_t* hash2) {
    for (size_t i = 0; i < 8; ++i) {
        if (hash1[i] < hash2[i]) {
            return true;
        } else if (hash1[i] > hash2[i]) {
            return false;
        }
    }
    return false;
}

__global__ void gpu_hash(uint64_t nonce_start, uint32_t *hashes, uint64_t *nonces) {
    union {
        char     bytes[64] = "DeltaNeverUsed/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        uint32_t ints[16];
    } prefix;

    for (size_t itter = 0; itter < hashes_per_thread; itter++)
    {
        auto thread_id = threadIdx.x;
        auto block_id = blockIdx.x;
        auto global_id = thread_id + block_id * blockDim.x;
        uint64_t nonce = (global_id + nonce_start) * hashes_per_thread + itter;
        uint64_t n = nonce;

        auto m_len = message_prefix_len + 16;
        for (size_t i = message_prefix_len-1; i < m_len-1; i++)
        {
            prefix.bytes[i] = chars[nonce % 62];
            nonce /= 62;
            if (nonce < 0)
                nonce = 0;
        }

        prefix.ints[15] = __byte_perm((m_len-1) * 8, 0, 0x0123);
        

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

        /*
        print_message(message);
        print_message(message + 64);
        print_message(message + 64 * 2);
        print_message(message + 64 * 3);
        */
    
        constexpr uint32_t h0[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

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

        auto index = global_id * 8;

        if (itter == 0) {
            hashes[index] = a + h0[0]; //__byte_perm(a + h0[0], 0, 0x0123);
            hashes[index + 1] = b + h0[1]; //__byte_perm(b + h0[1], 0, 0x0123);
            hashes[index + 2] = c + h0[2]; //__byte_perm(c + h0[2], 0, 0x0123);
            hashes[index + 3] = d + h0[3]; //__byte_perm(d + h0[3], 0, 0x0123);
            hashes[index + 4] = e + h0[4]; //__byte_perm(e + h0[4], 0, 0x0123);
            hashes[index + 5] = f + h0[5]; //__byte_perm(f + h0[5], 0, 0x0123);
            hashes[index + 6] = g + h0[6]; //__byte_perm(g + h0[6], 0, 0x0123);
            hashes[index + 7] = h + h0[7]; //__byte_perm(h + h0[7], 0, 0x0123);
            nonces[global_id] = n;
        } else {
            uint32_t hash[8];
            hash[0] = a + h0[0];
            hash[1] = b + h0[1];
            hash[2] = c + h0[2];
            hash[3] = d + h0[3];
            hash[4] = e + h0[4];
            hash[5] = f + h0[5];
            hash[6] = g + h0[6];
            hash[7] = h + h0[7];

            if (is_hash_smaller(hash, hashes + index)) {
                hashes[index] = hash[0];
                hashes[index + 1] = hash[1];
                hashes[index + 2] = hash[2];
                hashes[index + 3] = hash[3];
                hashes[index + 4] = hash[4];
                hashes[index + 5] = hash[5];
                hashes[index + 6] = hash[6];
                hashes[index + 7] = hash[7];
                nonces[global_id] = n;
            }
        }
    }
    
    //prefix.bytes[m_len-1] = 0;
    //printf(prefix.bytes);
    //printf("\n%x%x%x%x%x%x%x%x\n", ht[0], ht[1], ht[2], ht[3], ht[4], ht[5], ht[6], ht[7]);
}

void get_print_hash(uint64_t nonce) {
    char bytes[64] = "DeltaNeverUsed/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    auto m_len = message_prefix_len + 16;
    for (size_t i = message_prefix_len-1; i < m_len-1; i++)
    {
        bytes[i] = chars[nonce % 62];
        nonce /= 62;
        if (nonce < 0)
            nonce = 0;
    }

    printf(bytes);
}

int main() {

    uint32_t current_best_hash[8];
    for (size_t i = 0; i < 8; i++)
        current_best_hash[i] = 0xFFFFFFFF;

    uint64_t nonce_start = 2127366416;

    auto grid_dim = 38 * 2;
    auto block_dim = 256;

    size_t arr_size = block_dim * grid_dim;
    size_t arr_size_bytes = arr_size * sizeof(uint32_t) * 8;

    uint64_t* nonces = (uint64_t*)malloc(arr_size * sizeof(uint64_t));
    uint32_t* hashes = (uint32_t*)malloc(arr_size_bytes);
    uint32_t* device_hashes;
    uint64_t* device_nonces;

    cudaMalloc(&device_hashes, arr_size_bytes);
    cudaMalloc(&device_nonces, arr_size * sizeof(uint64_t));

    uint64_t hashes_done = 0;
    auto hash_start = std::chrono::high_resolution_clock::now();
    
    gpu_hash<<<grid_dim, block_dim>>>(nonce_start, device_hashes, device_nonces);
    while (true)
    {
        cudaDeviceSynchronize();
        cudaMemcpy(hashes, device_hashes, arr_size_bytes, cudaMemcpyDeviceToHost);
        cudaMemcpy(nonces, device_nonces, arr_size * sizeof(uint64_t), cudaMemcpyDeviceToHost);
        gpu_hash<<<grid_dim, block_dim>>>(nonce_start + arr_size * hashes_per_thread, device_hashes, device_nonces);
        hashes_done += arr_size * hashes_per_thread;

        if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()-hash_start) >= std::chrono::seconds(10)) {
            hash_start += std::chrono::seconds(10);
            printf("\nHashrate: %fGH/s\n", hashes_done / 1000000000. / 10);
            hashes_done = 0;
        }
        
        for (size_t i = 0; i < arr_size; i++)
        {
            auto v = i * 8;
            if (is_hash_smaller(hashes + v, current_best_hash)) {
                printf("i: %u v: %u\n", i, v);
                current_best_hash[0] = hashes[v];
                current_best_hash[1] = hashes[1 + v];
                current_best_hash[2] = hashes[2 + v];
                current_best_hash[3] = hashes[3 + v];
                current_best_hash[4] = hashes[4 + v];
                current_best_hash[5] = hashes[5 + v];
                current_best_hash[6] = hashes[6 + v];
                current_best_hash[7] = hashes[7 + v];

                char temp[80];

                printf("Smaller hash found!\n");
                get_print_hash(nonces[i]);
                sprintf(temp, "\n%08x%08x%08x%08x%08x%08x%08x%08x\n", current_best_hash[0], current_best_hash[1], current_best_hash[2], current_best_hash[3], current_best_hash[4], current_best_hash[5], current_best_hash[6], current_best_hash[7]);
                printf(temp);
                
                for (size_t j = 0; j < 64; j++){
                    if (temp[j+1] != '0') {
                        printf("Got %u zeros\n\n", j);
                        break;
                    }
                }

                printf("%u\n", nonces[i]);
                
            }
        }


        nonce_start += arr_size * hashes_per_thread;
    }
    
    cudaFree(device_nonces);
    cudaFree(device_hashes);
}