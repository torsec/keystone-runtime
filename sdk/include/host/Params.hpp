//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <cstdio>

#if __riscv_xlen == 64
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#elif __riscv_xlen == 32
#define DEFAULT_FREEMEM_SIZE 1024 * 512  // 512 KiB
#define DEFAULT_UNTRUSTED_PTR 0x80000000
#define DEFAULT_STACK_SIZE 1024 * 8  // 3 KiB
#define DEFAULT_STACK_START 0x40000000
#else                                     // for x86 tests
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#endif

#define DEFAULT_UNTRUSTED_SIZE 8192  // 8 KB
#define DEFAULT_UUID_LEN 37  // UUID length (36 characters + null terminator)

/* parameters for enclave creation */
namespace Keystone {

class Params {
 public:
  Params() {
    untrusted_size = DEFAULT_UNTRUSTED_SIZE;
    freemem_size   = DEFAULT_FREEMEM_SIZE;
    std::fill(std::begin(uuid), std::end(uuid), 0x00);
  }

  void setUntrustedSize(uint64_t size) { untrusted_size = size; }
  void setFreeMemSize(uint64_t size) { freemem_size = size; }
  void setUuid(const char* uuid_str) { snprintf((char*)uuid, DEFAULT_UUID_LEN, "%s", uuid_str); }
  uintptr_t getUntrustedSize() { return untrusted_size; }
  uintptr_t getFreeMemSize() { return freemem_size; }
  const unsigned char* getUuid() { return uuid; }

 private:
  uint64_t untrusted_size;
  uint64_t freemem_size;
  unsigned char uuid[DEFAULT_UUID_LEN];  // UUID for the enclave
};

}  // namespace Keystone
