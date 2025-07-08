/* Default platform does nothing special here */
#include "../../enclave.h"
#include <sbi/sbi_string.h>

unsigned long platform_init_global_once(){
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_init_global(){
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_init_enclave(struct enclave* enclave){
  return;
}

void platform_destroy_enclave(struct enclave* enclave){
  return;
}

unsigned long platform_create_enclave(struct enclave* enclave){
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave* enclave){
  return;
}

void platform_switch_from_enclave(struct enclave* enclave){
  return;
}

uint64_t platform_random(){
#pragma message("Platform has no entropy source, this is unsafe. TEST ONLY")
  static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;

  unsigned long cycles;
  asm volatile ("rdcycle %0" : "=r" (cycles));

  // from Middle Square Weyl Sequence algorithm
  uint64_t x = cycles;
  x *= x;
  x += (w += s);
  return (x>>32) | (x<<32);
}

// Initialization functions

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_sm_cert[CERT_SIZE];
extern byte sanctum_dev_cert[CERT_SIZE];
extern byte sanctum_man_cert[CERT_SIZE];
extern int sanctum_sm_cert_len;
extern int sanctum_dev_cert_len;
extern int sanctum_man_cert_len;

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte dev_public_key[PUBLIC_KEY_SIZE];
extern byte sm_cert[CERT_SIZE];
extern byte dev_cert[CERT_SIZE];
extern byte man_cert[CERT_SIZE];
extern int sm_cert_len;
extern int dev_cert_len;
extern int man_cert_len;

void sm_copy_key(void)
{
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_cert, sanctum_sm_cert, CERT_SIZE);
  sbi_memcpy(dev_cert, sanctum_dev_cert, CERT_SIZE);
  sbi_memcpy(man_cert, sanctum_man_cert, CERT_SIZE);
  sm_cert_len = sanctum_sm_cert_len;
  dev_cert_len = sanctum_dev_cert_len;
  man_cert_len = sanctum_man_cert_len;
}
