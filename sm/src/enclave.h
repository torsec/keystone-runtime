//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "pmp.h"
#include "thread.h"
#include <crypto.h>

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  1024

/* TODO: does not support multithreaded enclave yet */
#define MAX_ENCL_THREADS 1

#define PRINT_TICKS 1

typedef uintptr_t pte_t;

typedef enum {
  INVALID = -1,
  DESTROYING = 0,
  ALLOCATED,
  FRESH,
  STOPPED,
  RUNNING,
} enclave_state;

/* For now, eid's are a simple unsigned int */
typedef unsigned int enclave_id;

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
enum enclave_region_type{
  REGION_INVALID,
  REGION_EPM,
  REGION_UTM,
  REGION_OTHER,
};

struct enclave_region
{
  region_id pmp_rid;
  enum enclave_region_type type;
};

/* enclave metadata */
struct enclave
{
  //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
  enclave_id eid;                   // enclave id
  unsigned char uuid[UUID_LEN];     // UUID externally provided, must be unique
  unsigned long encl_satp;          // enclave's page table base
  enclave_state state;              // global state of the enclave

  /* Physical memory regions associate with this enclave */
  struct enclave_region regions[ENCLAVE_REGIONS_MAX];

  /* measurement */
  byte hash[MDSIZE];
  byte runtime_hash[MDSIZE];
  byte sign[SIGNATURE_SIZE];

  // DICE parameters
  byte CDI[64];
  byte local_att_pub[32];
  byte local_att_priv[64];
  mbedtls_x509write_cert crt_local_att;
  // Convert crt_local_att to DER format using "mbedtls_x509write_crt_der" when needed to save space.
  // unsigned char crt_local_att_der[MAX_CERT_LEN];
  // int crt_local_att_der_length;

  byte pk_ldev[32];
  byte sk_ldev[64];
  mbedtls_x509write_cert crt_ldev;
  // unsigned char crt_ldev_der[MAX_CERT_LEN];
  // int crt_ldev_der_length;

  // byte sk_array[10][64];
  // byte pk_array[10][32];
  int n_keypair;

  /* parameters */
  struct runtime_params_t params;

  /* enclave execution context */
  unsigned int n_thread;
  struct thread_state threads[MAX_ENCL_THREADS];

  struct platform_enclave_data ped;
};

/* attestation reports */
struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};
struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};
struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

/* runtime attestation reports */
struct enclave_runtime_report
{
  byte uuid[UUID_LEN];
  byte hash[MDSIZE];
  byte signature[SIGNATURE_SIZE];     // sign(hash || nonce)
};
struct runtime_report
{
  struct enclave_runtime_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
  byte nonce[NONCE_LEN];
};

// DICE attestation certificate chain (man, root, SM, LAK)
struct dice_attestation_cert_chain
{
  unsigned char certs[4][MAX_CERT_LEN];
  int certs_len[4];
  byte uuid[UUID_LEN];
};

/* sealing key structure */
#define SEALING_KEY_SIZE 128
struct sealing_key
{
  uint8_t key[SEALING_KEY_SIZE];
  uint8_t signature[SIGNATURE_SIZE];
};

struct lak_cert_args
{
    unsigned char uuid[UUID_LEN];
    unsigned char cert_lak[MAX_CERT_LEN];
    int cert_len;
};


/*** SBI functions & external functions ***/
// callables from the host
unsigned long create_enclave(unsigned long *eid, struct keystone_sbi_create_t create_args);
unsigned long destroy_enclave(enclave_id eid);
unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long compute_enclave_runtime_hash(struct enclave* enclave);
// callables from the enclave
unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid);
unsigned long attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);
// attestation
unsigned long validate_and_hash_enclave(struct enclave* enclave);
unsigned long runtime_attestation(struct runtime_report *report);
unsigned long get_dice_cert_chain(struct dice_attestation_cert_chain *cert_chain);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata(void);
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest);
unsigned long copy_runtime_attestation_report_into_sm(uintptr_t src, struct runtime_report* dest);
unsigned long copy_runtime_attestation_report_from_sm(struct runtime_report* src, uintptr_t dest);
unsigned long copy_cert_chain_data_into_sm(uintptr_t src, struct dice_attestation_cert_chain* dest);
unsigned long copy_cert_chain_data_from_sm(struct dice_attestation_cert_chain* src, uintptr_t dest);
int get_enclave_region_index(enclave_id eid, enum enclave_region_type type);
uintptr_t get_enclave_region_base(enclave_id eid, int memid);
uintptr_t get_enclave_region_size(enclave_id eid, int memid);
unsigned long get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size, enclave_id eid);
// interrupt handlers
void sbi_trap_handler_keystone_enclave(struct sbi_trap_regs *regs);

#endif
