#ifndef __SM_CALL_H__
#define __SM_CALL_H__

// BKE (Berkeley Keystone Enclave)
#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

/* 0-1999 are not used (deprecated) */
#define FID_RANGE_DEPRECATED      1999
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE     2001
#define SBI_SM_DESTROY_ENCLAVE    2002
#define SBI_SM_RUN_ENCLAVE        2003
#define SBI_SM_RESUME_ENCLAVE     2005
#define SBI_SM_RUNTIME_ATTEST     2006
#define SBI_SM_GET_LAK_CERT       2007
#define FID_RANGE_HOST            2999

/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM             3001
#define SBI_SM_ATTEST_ENCLAVE     3002
#define SBI_SM_GET_SEALING_KEY    3003
#define SBI_SM_STOP_ENCLAVE       3004
#define SBI_SM_EXIT_ENCLAVE       3006
#define FID_RANGE_ENCLAVE         3999

/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID     0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* Defines for enclave structs */
#define MDSIZE                64
#define NONCE_LEN             20
#define UUID_LEN              37
#define PUBLIC_KEY_SIZE       32
#define SIGNATURE_SIZE        64
#define MAX_CERT_LEN          512

typedef unsigned char byte;

/* Structs for interfacing into the SM */
struct runtime_params_t {
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
  uintptr_t untrusted_base;
  uintptr_t untrusted_size;
  uintptr_t free_requested; // for attestation
};

struct keystone_sbi_pregion_t {
  uintptr_t paddr;
  size_t size;
};

struct keystone_sbi_create_t {
  struct keystone_sbi_pregion_t epm_region;
  struct keystone_sbi_pregion_t utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;

  unsigned char uuid[UUID_LEN];
};

struct enclave_runtime_report_t {
  byte uuid[UUID_LEN];
  byte hash[MDSIZE];
  byte signature[SIGNATURE_SIZE];
};

struct sm_runtime_report_t {
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct keystone_sbi_runtime_attestation_t {
  struct enclave_runtime_report_t enclave;
  struct sm_runtime_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
  byte nonce[NONCE_LEN];
};

// DICE attestation certificate chain (man, root, SM, LAK)
struct keystone_sbi_dice_attestation_cert_chain_t {
  unsigned char certs[4][MAX_CERT_LEN];
  int certs_len[4];
  byte uuid[UUID_LEN];
};

#endif  // __SM_CALL_H__
