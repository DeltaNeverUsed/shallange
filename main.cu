#include <stdio.h>
#include <cuda/std/bit>
#include <chrono>
#include <thread>
#include <vector>
//               DeltaNeverUsed/VRC/3+8GHs3060TI/________________/______
//               aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#define MESSAGE "DeltaNeverUsed/VRC/3+8GHs3060TI/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0/000000\0\0\0\0\0\0\0\0"

__device__ constexpr uint64_t hashes_per_thread = 0x100000;
__device__ constexpr char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

__device__ constexpr uint_fast8_t message_prefix_len = 32;
__device__ constexpr uint_fast8_t message_suffix_len = 7;

__device__ constexpr uint32_t K[64] = { 
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
 };

__device__ inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

__device__ inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ inline uint32_t Sigma0(uint32_t x) {
    return cuda::std::rotr(x, 2) ^ cuda::std::rotr(x, 13) ^ cuda::std::rotr(x, 22);
}

__device__ inline uint32_t Sigma1(uint32_t x) {
    return cuda::std::rotr(x, 6) ^ cuda::std::rotr(x, 11) ^ cuda::std::rotr(x, 25);
}

__device__ inline uint32_t sigma0(uint32_t x) {
    return cuda::std::rotr(x, 7) ^ cuda::std::rotr(x, 18) ^ (x >> 3);
}

__device__ inline uint32_t sigma1(uint32_t x) {
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
    #pragma unroll
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
        char     bytes[64] = MESSAGE;
        uint32_t ints[16];
    } prefix;

    prefix.bytes[55] = 0x80;

    auto thread_id = threadIdx.x;
    auto block_id = blockIdx.x;
    auto global_id = thread_id + block_id * blockDim.x;

    auto hash_index = global_id * 8;

    hashes[hash_index] = 0xFFFFFFFF;
    hashes[hash_index + 1] = 0xFFFFFFFF;
    hashes[hash_index + 2] = 0xFFFFFFFF;
    hashes[hash_index + 3] = 0xFFFFFFFF;
    hashes[hash_index + 4] = 0xFFFFFFFF;
    hashes[hash_index + 5] = 0xFFFFFFFF;
    hashes[hash_index + 6] = 0xFFFFFFFF;
    hashes[hash_index + 7] = 0xFFFFFFFF;

    uint64_t nonce_p1 = nonce_start + (global_id * hashes_per_thread);
    constexpr auto m_len = message_prefix_len + 16;

    union {
        uint8_t  message[512];
        uint32_t words[64];
    };

    #pragma unroll
    for (uint_fast8_t i = 0; i < 64; i+=4)
    {
        #pragma unroll
        for (uint_fast8_t l = 0; l < 4; l++)
        {
            message[i + l] = prefix.bytes[i + 3 - l];
        }
    }

    words[15] = (m_len + message_suffix_len) * 8;

    for (uint32_t itter = 0; itter < hashes_per_thread; itter++)
    {
        uint64_t nonce = nonce_p1 + itter;
        uint64_t n = nonce;

        #pragma unroll
        for (uint_fast8_t i = message_prefix_len; i < m_len; i++)
        {
            prefix.bytes[i] = chars[nonce & 63];
            nonce >>= 6;
        }

        #pragma unroll
        for (uint_fast8_t i = message_prefix_len; i < message_prefix_len+16; i+=4)
        {
            #pragma unroll
            for (uint_fast8_t l = 0; l < 4; l++)
            {
                message[i + l] = prefix.bytes[i + 3 - l];
            }
        }

        #pragma unroll
        for (uint_fast8_t i = 16; i < 64; i++)
        {
            words[i] = sigma1(words[i-2]) + words[i-7] + sigma0(words[i-15]) + words[i-16];
        }

        /*
        print_message(message);
        print_message(message + 64);
        print_message(message + 64 * 2);
        print_message(message + 64 * 3);
        */
    
        constexpr uint32_t h0[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

        union {
            struct {
                uint32_t a;
                uint32_t b;
                uint32_t c;
                uint32_t d;
                uint32_t e;
                uint32_t f;
                uint32_t g;
                uint32_t h;
            };
            uint32_t arr[8];
        } u = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        
        #pragma unroll
        for (uint_fast8_t i = 0; i < 64; i++)
        {
            uint32_t t1 = u.h + Sigma1(u.e) + Ch(u.e,u.f,u.g) + K[i] + words[i];
            uint32_t t2 = Sigma0(u.a) + Maj(u.a,u.b,u.c);

            u.h = u.g;
            u.g = u.f;
            u.f = u.e;
            u.e = u.d + t1;
            u.d = u.c;
            u.c = u.b;
            u.b = u.a;
            u.a = t1 + t2;
        }

        auto new_better = false;
        uint_fast8_t i = 0;
        #pragma unroll
        for (;i < 4; ++i) {
            u.arr[i] = u.arr[i] + h0[i];
            if (u.arr[i] < hashes[hash_index + i]) {
                new_better = true;
                break;
            } else if (u.arr[i] > hashes[hash_index + i]) {
                break;
            }
        }
        i++;
        if (new_better){
            #pragma unroll
            for (uint_fast8_t j = 0; j < i; j++)
            {
                hashes[hash_index + j] = u.arr[j];
            }

            #pragma unroll
            for (uint_fast8_t j = i; j < 8; j++)
            {
                hashes[hash_index + j] = u.arr[j] + h0[j];
            }
            nonces[global_id] = n;
        }
        
        
    }
}

void get_print_hash(uint64_t nonce) {
    char bytes[64] = MESSAGE;

    auto m_len = message_prefix_len + 16;
    for (uint_fast8_t i = message_prefix_len; i < m_len; i++)
    {
        bytes[i] = chars[nonce & 63];
        nonce >>= 6;
    }

    printf(bytes);
}

uint64_t hashes_done;

void hashrate_check() {
    while (true)
    {
        _sleep(1000000);
        
        printf("\nHashrate: %fGH/s\n", hashes_done / 1000000000. / 1000);
        hashes_done = 0;
    }
}

int main() {

    uint32_t current_best_hash[8];
    for (size_t i = 0; i < 8; i++)
        current_best_hash[i] = 0xFFFFFFFF;

    uint64_t nonce_start = 0;

    auto grid_dim = 38 * 2;
    auto block_dim = 256;

    size_t arr_size = block_dim * grid_dim;
    size_t arr_size_bytes = arr_size * sizeof(uint32_t) * 8;

    int num_gpus;
    cudaGetDeviceCount(&num_gpus);

    std::vector<uint64_t*> nonces(num_gpus);
    std::vector<uint32_t*> hashes(num_gpus);
    std::vector<uint32_t*> device_hashes(num_gpus);
    std::vector<uint64_t*> device_nonces(num_gpus);

    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);

        nonces[gpu] = (uint64_t*)malloc(arr_size * sizeof(uint64_t));
        hashes[gpu] = (uint32_t*)malloc(arr_size_bytes);
        cudaMalloc(&device_nonces[gpu], arr_size * sizeof(uint64_t));
        cudaMalloc(&device_hashes[gpu], arr_size_bytes);
    }
    
    std::thread check = std::thread(hashrate_check);

    for (int i = 0; i < num_gpus; i++) {
        cudaSetDevice(i);
        gpu_hash<<<grid_dim, block_dim>>>(nonce_start + i * arr_size * hashes_per_thread, device_hashes[i], device_nonces[i]);
    }
    while (true)
    {
        for (int gpu = 0; gpu < num_gpus; gpu++) {
            cudaSetDevice(gpu);
            cudaDeviceSynchronize();
            cudaMemcpy(hashes[gpu], device_hashes[gpu], arr_size_bytes, cudaMemcpyDeviceToHost);
            cudaMemcpy(nonces[gpu], device_nonces[gpu], arr_size * sizeof(uint64_t), cudaMemcpyDeviceToHost);
            gpu_hash<<<grid_dim, block_dim>>>(nonce_start + gpu * arr_size * hashes_per_thread, device_hashes[gpu], device_nonces[gpu]);
        }

        hashes_done += arr_size * hashes_per_thread * num_gpus;
        
        for (int gpu = 0; gpu < num_gpus; gpu++) {
            for (size_t i = 0; i < arr_size; i++)
            {
                auto v = i * 8;
                uint32_t *currentHash = hashes[gpu];
                if (is_hash_smaller(currentHash + v, current_best_hash)) {
                    printf("i: %u v: %u\n", i, v);
                    current_best_hash[0] = currentHash[v];
                    current_best_hash[1] = currentHash[1 + v];
                    current_best_hash[2] = currentHash[2 + v];
                    current_best_hash[3] = currentHash[3 + v];
                    current_best_hash[4] = currentHash[4 + v];
                    current_best_hash[5] = currentHash[5 + v];
                    current_best_hash[6] = currentHash[6 + v];
                    current_best_hash[7] = currentHash[7 + v];

                    char temp[80];

                    printf("Smaller hash found! on GPU: %u\n", gpu);
                    get_print_hash(nonces[gpu][i]);
                    sprintf(temp, "\n%08x%08x%08x%08x%08x%08x%08x%08x\n", current_best_hash[0], current_best_hash[1], current_best_hash[2], current_best_hash[3], current_best_hash[4], current_best_hash[5], current_best_hash[6], current_best_hash[7]);
                    printf(temp);
                    
                    for (size_t j = 0; j < 64; j++){
                        if (temp[j+1] != '0') {
                            printf("Got %llu zeros\n\n", j);
                            break;
                        }
                    }

                    printf("%llu\n", nonces[gpu][i]);
                    
                }
            }
        }

        nonce_start += arr_size * hashes_per_thread * num_gpus;
    }
    
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaFree(device_hashes[gpu]);
        cudaFree(device_nonces[gpu]);
        free(hashes[gpu]);
        free(nonces[gpu]);
    }
}