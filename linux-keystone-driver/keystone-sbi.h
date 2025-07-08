//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_
#define _KEYSTONE_SBI_

#include "keystone_user.h"
// #include "sm_call.h"

#include <asm/sbi.h>

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args);
struct sbiret sbi_sm_destroy_enclave(unsigned long eid);
struct sbiret sbi_sm_run_enclave(unsigned long eid);
struct sbiret sbi_sm_resume_enclave(unsigned long eid);
struct sbiret sbi_sm_runtime_attestation(struct keystone_sbi_runtime_attestation_t* args);
struct sbiret sbi_sm_get_dice_cert_chain(struct keystone_sbi_dice_attestation_cert_chain_t* args);

#endif
