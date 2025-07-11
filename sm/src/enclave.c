//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"

#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_string.h>

#include "cpu.h"
#include "mprv.h"
#include "page.h"
#include "platform-hook.h"
#include "pmp.h"
 #if PRINT_TICKS
#include <sbi/sbi_timer.h>
#endif

struct enclave enclaves[ENCL_MAX];

// Enclave IDs are unsigned ints, so we do not need to check if eid is
// greater than or equal to 0
#define ENCLAVE_EXISTS(eid) (eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];
extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte sm_cert[CERT_SIZE];
extern byte dev_cert[CERT_SIZE];
extern byte man_cert[CERT_SIZE];
extern int sm_cert_len;
extern int dev_cert_len;
extern int man_cert_len;

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Retrieve an enclave id given the UUID of an enclave*/
static inline enclave_id get_enclave_id_by_uuid(byte *uuid) {
    enclave_id eid;
    for (eid = 0; eid < ENCL_MAX; eid++) {
        if (enclaves[eid].state != INVALID)
            if (sbi_memcmp(enclaves[eid].uuid, (char *)uuid, UUID_LEN - 1) == 0)
                return eid;
    }

    return -1;
}

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
 */
static inline void context_switch_to_enclave(struct sbi_trap_regs *regs,
                                             enclave_id eid,
                                             int load_parameters) {
    /* save host context */
    swap_prev_state(&enclaves[eid].threads[0], regs, 1);
    swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
    swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

    uintptr_t interrupts = 0;
    csr_write(mideleg, interrupts);

    if (load_parameters) {
        // passing parameters for a first run
        regs->mepc = (uintptr_t)enclaves[eid].params.dram_base - 4;  // regs->mepc will be +4 before sbi_ecall_handler return
        regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
        // $a1: (PA) DRAM base,
        regs->a1 = (uintptr_t)enclaves[eid].params.dram_base;
        // $a2: DRAM size,
        regs->a2 = (uintptr_t)enclaves[eid].params.dram_size;
        // $a3: (PA) kernel location,
        regs->a3 = (uintptr_t)enclaves[eid].params.runtime_base;
        // $a4: (PA) user location,
        regs->a4 = (uintptr_t)enclaves[eid].params.user_base;
        // $a5: (PA) freemem location,
        regs->a5 = (uintptr_t)enclaves[eid].params.free_base;
        // $a6: (PA) utm base,
        regs->a6 = (uintptr_t)enclaves[eid].params.untrusted_base;
        // $a7: utm size
        regs->a7 = (uintptr_t)enclaves[eid].params.untrusted_size;

        // enclave will only have physical addresses in the first run
        csr_write(satp, 0);
    }

    switch_vector_enclave();

    // set PMP
    osm_pmp_set(PMP_NO_PERM);
    int memid;
    for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
        if (enclaves[eid].regions[memid].type != REGION_INVALID) {
            pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
        }
    }

    // Setup any platform specific defenses
    platform_switch_to_enclave(&(enclaves[eid]));
    cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
                                          enclave_id eid,
                                          int return_on_resume) {
    // set PMP
    int memid;
    for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
        if (enclaves[eid].regions[memid].type != REGION_INVALID) {
            pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
        }
    }
    osm_pmp_set(PMP_ALL_PERM);

    uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
    csr_write(mideleg, interrupts);

    /* restore host context */
    swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
    swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
    swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

    switch_vector_host();

    uintptr_t pending = csr_read(mip);

    if (pending & MIP_MTIP) {
        csr_clear(mip, MIP_MTIP);
        csr_set(mip, MIP_STIP);
    }
    if (pending & MIP_MSIP) {
        csr_clear(mip, MIP_MSIP);
        csr_set(mip, MIP_SSIP);
    }
    if (pending & MIP_MEIP) {
        csr_clear(mip, MIP_MEIP);
        csr_set(mip, MIP_SEIP);
    }

    // Reconfigure platform specific defenses
    platform_switch_from_enclave(&(enclaves[eid]));

    cpu_exit_enclave_context();

    return;
}

// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(void) {
    enclave_id eid;
    int i = 0;

    /* Assumes eids are incrementing values, which they are for now */
    for (eid = 0; eid < ENCL_MAX; eid++) {
        enclaves[eid].state = INVALID;

        // Clear out regions
        for (i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
            enclaves[eid].regions[i].type = REGION_INVALID;
        }
        /* Fire all platform specific init for each enclave */
        platform_init_enclave(&(enclaves[eid]));
    }
}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize) {
    // This function is quite temporary. See issue #38

    // Zero out the untrusted memory region, since it may be in
    // indeterminate state.
    sbi_memset((void *)utbase, 0, utsize);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id *_eid) {
    enclave_id eid;

    spin_lock(&encl_lock);

    for (eid = 0; eid < ENCL_MAX; eid++) {
        if (enclaves[eid].state == INVALID) {
            break;
        }
    }
    if (eid != ENCL_MAX)
        enclaves[eid].state = ALLOCATED;

    spin_unlock(&encl_lock);

    if (eid != ENCL_MAX) {
        *_eid = eid;
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
    } else {
        return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    }
}

static unsigned long encl_free_eid(enclave_id eid) {
    spin_lock(&encl_lock);
    enclaves[eid].state = INVALID;
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type) {
    size_t i;
    for (i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
        if (enclaves[eid].regions[i].type == type) {
            return i;
        }
    }
    // No such region for this enclave
    return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid) {
    if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
        return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

    return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid) {
    if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
        return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

    return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t *dest) {
    int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));

    if (region_overlap)
        return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave *enclave,
                                       void *dest, uintptr_t source, size_t size) {
    int illegal = copy_to_sm(dest, source, size);

    if (illegal)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave *enclave,
                                         uintptr_t dest, struct report *source) {
    int illegal = copy_from_sm(dest, source, sizeof(struct report));

    if (illegal)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_runtime_attestation_report_into_sm(uintptr_t src, struct runtime_report *dest) {
    if (copy_to_sm(dest, src, sizeof(struct runtime_report)))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_runtime_attestation_report_from_sm(struct runtime_report *src, uintptr_t dest) {
    if (copy_from_sm(dest, src, sizeof(struct runtime_report)))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_cert_chain_data_into_sm(uintptr_t src, struct dice_attestation_cert_chain* dest) {
    if (copy_to_sm(dest, src, sizeof(struct dice_attestation_cert_chain)))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_cert_chain_data_from_sm(struct dice_attestation_cert_chain* src, uintptr_t dest) {
    if (copy_from_sm(dest, src, sizeof(struct dice_attestation_cert_chain)))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create_t *args) {
    uintptr_t epm_start, epm_end;

    /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
    /*        args->epm_region.paddr, */
    /*        args->epm_region.size, */
    /*        args->utm_region.paddr, */
    /*        args->utm_region.size, */
    /*        args->runtime_paddr, */
    /*        args->user_paddr, */
    /*        args->free_paddr); */

    // check if physical addresses are valid
    if (args->epm_region.size <= 0)
        return 0;

    // check if overflow
    if (args->epm_region.paddr >=
        args->epm_region.paddr + args->epm_region.size)
        return 0;
    if (args->utm_region.paddr >=
        args->utm_region.paddr + args->utm_region.size)
        return 0;

    epm_start = args->epm_region.paddr;
    epm_end = args->epm_region.paddr + args->epm_region.size;

    // check if physical addresses are in the range
    if (args->runtime_paddr < epm_start ||
        args->runtime_paddr >= epm_end)
        return 0;
    if (args->user_paddr < epm_start ||
        args->user_paddr >= epm_end)
        return 0;
    if (args->free_paddr < epm_start ||
        args->free_paddr > epm_end)
        // note: free_paddr == epm_end if there's no free memory
        return 0;

    // check the order of physical addresses
    if (args->runtime_paddr > args->user_paddr)
        return 0;
    if (args->user_paddr > args->free_paddr)
        return 0;

    return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/

/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create_t create_args) {
    /* EPM and UTM parameters */
    uintptr_t base = create_args.epm_region.paddr;
    size_t size = create_args.epm_region.size;
    uintptr_t utbase = create_args.utm_region.paddr;
    size_t utsize = create_args.utm_region.size;

    byte CDI[64];
    sha3_ctx_t hash_ctx_to_use;
    // Variable used to specify the serial of the cert
    unsigned char serial[] = {0x0};

    unsigned char *cert_real;
    int dif = 0;

    enclave_id eid;
    unsigned long ret;
    int region, shared_region;

    /* Runtime parameters */
    if (!is_create_args_valid(&create_args))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

    /* set params */
    struct runtime_params_t params;
    params.dram_base = base;
    params.dram_size = size;
    params.runtime_base = create_args.runtime_paddr;
    params.user_base = create_args.user_paddr;
    params.free_base = create_args.free_paddr;
    params.untrusted_base = utbase;
    params.untrusted_size = utsize;
    params.free_requested = create_args.free_requested;

    // allocate eid
    ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
        goto error;

    // create a PMP region bound to the enclave
    ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    if (pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
        goto free_encl_idx;

    // create PMP region for shared memory
    if (pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
        goto free_region;

    // set pmp registers for private region (not shared)
    if (pmp_set_global(region, PMP_NO_PERM))
        goto free_shared_region;

    // cleanup some memory regions for sanity See issue #38
    clean_enclave_memory(utbase, utsize);

    // initialize enclave metadata
    enclaves[eid].eid = eid;

    sbi_strncpy((char *)enclaves[eid].uuid, (const char *)create_args.uuid, UUID_LEN);
    sbi_printf("[SM] Enclave %d UUID set to %s\n", eid, enclaves[eid].uuid);

    enclaves[eid].regions[0].pmp_rid = region;
    enclaves[eid].regions[0].type = REGION_EPM;
    enclaves[eid].regions[1].pmp_rid = shared_region;
    enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
    enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
    enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
    enclaves[eid].n_thread = 0;
    enclaves[eid].params = params;

    /* Init enclave state (regs etc) */
    clean_state(&enclaves[eid].threads[0]);

    /* Platform create happens as the last thing before hashing/etc since
       it may modify the enclave struct */
    ret = platform_create_enclave(&enclaves[eid]);
    if (ret)
        goto unset_region;

    /* Validate memory, prepare hash and signature for attestation */
    spin_lock(&encl_lock);  // FIXME This should error for second enter.

    ret = validate_and_hash_enclave(&enclaves[eid]);
    /* The enclave is fresh if it has been validated and hashed but not run yet. */
    if (ret)
        goto unlock;

    enclaves[eid].state = FRESH;
    /* EIDs are unsigned int in size, copy via simple copy */
    *eidptr = eid;

    sha3_init(&hash_ctx_to_use, 64);
    sha3_update(&hash_ctx_to_use, CDI, 64);
    sha3_update(&hash_ctx_to_use, enclaves[eid].hash, 64);
    sha3_final(enclaves[eid].CDI, &hash_ctx_to_use);

    ed25519_create_keypair(enclaves[eid].local_att_pub, enclaves[eid].local_att_priv, enclaves[eid].CDI);

    sbi_printf("[SM] LAK (public): 0x");
    for (int i = 0; i < 32; i++)
        sbi_printf("%02x", enclaves[eid].local_att_pub[i]);
    sbi_printf("\n");

    mbedtls_x509write_crt_init(&enclaves[eid].crt_local_att);

    ret = mbedtls_x509write_crt_set_issuer_name_mod(&enclaves[eid].crt_local_att, "CN=Security Monitor");
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }

    // Setting the name of the subject of the cert
    ret = mbedtls_x509write_crt_set_subject_name_mod(&enclaves[eid].crt_local_att, "CN=Enclave LAK");
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }

    // pk context used to embed the keys of the security monitor
    mbedtls_pk_context subj_key;
    mbedtls_pk_init(&subj_key);

    // pk context used to embed the keys of the embedded CA
    mbedtls_pk_context issu_key;
    mbedtls_pk_init(&issu_key);

    // The keys of the embedded CA are used to sign the different certs associated to the local attestation keys of the different enclaves
    ret = mbedtls_pk_parse_public_key(&issu_key, sm_private_key, 64, 1);
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }
    ret = mbedtls_pk_parse_public_key(&issu_key, sm_public_key, 32, 0);
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }

    // Parsing the public key of the enclave that will be inserted in its certificate
    ret = mbedtls_pk_parse_public_key(&subj_key, enclaves[eid].local_att_pub, 32, 0);
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }

    serial[0] = eid;

    // The public key of the enclave is inserted in the structure
    mbedtls_x509write_crt_set_subject_key(&enclaves[eid].crt_local_att, &subj_key);

    // The private key of the embedded CA is used later to sign the cert
    mbedtls_x509write_crt_set_issuer_key(&enclaves[eid].crt_local_att, &issu_key);

    // The serial of the cert is setted
    mbedtls_x509write_crt_set_serial_raw(&enclaves[eid].crt_local_att, serial, 1);

    // The algoithm used to do the hash for the signature is specified
    mbedtls_x509write_crt_set_md_alg(&enclaves[eid].crt_local_att, KEYSTONE_SHA3);

    mbedtls_x509write_crt_set_key_usage(&enclaves[eid].crt_local_att, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

    // The validity of the crt is specified
    ret = mbedtls_x509write_crt_set_validity(&enclaves[eid].crt_local_att, "20230101000000", "20260101000000");
    if (ret != 0) {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }
    // const char oid_ext[] = {0xff, 0x20, 0xff};
    // const char oid_ext2[] = {0x55, 0x1d, 0x13};
    // unsigned char max_path[] = {0x0A};
    dice_tcbInfo tcbInfo;
    init_dice_tcbInfo(&tcbInfo);

    measure m;
    const unsigned char OID_algo[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A};
    m.oid_len = 9;
    // unsigned char app[64];
    sbi_memcpy(m.OID_algho, OID_algo, m.oid_len);
    sbi_memcpy(m.digest, enclaves[eid].hash, 64);

    set_dice_tcbInfo_measure(&tcbInfo, m);

    int dim = 324;
    unsigned char buf[324];

    if (mbedtls_x509write_crt_set_dice_tcbInfo(&enclaves[eid].crt_local_att, tcbInfo, dim, buf, sizeof(buf)) != 0)
        sbi_printf("\nError setting DICETCB extension!\n");

    unsigned char cert_der[1024];
    int effe_len_cert_der = 0;
    size_t len_cert_der_tot = 1024;

    ret = mbedtls_x509write_crt_der(&enclaves[eid].crt_local_att, cert_der, len_cert_der_tot, NULL, NULL);

    if (ret > 0) {
        effe_len_cert_der = ret;
        ret = 0;
    } else {
        ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
        goto unlock;
    }
    cert_real = cert_der;
    dif = 0;
    dif = 1024 - effe_len_cert_der;
    cert_real += dif;

    // The der format of the cert and its length are stored in the specific variables of the enclave structure
    // enclaves[eid].crt_local_att_der_length = effe_len_cert_der;
    // sbi_memcpy(enclaves[eid].crt_local_att_der, cert_real, effe_len_cert_der);

    // The number of the keypair associated to the created enclave that are not the local attestation keys is set to 0
    enclaves[eid].n_keypair = 0;

    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
    spin_unlock(&encl_lock);
    // free_platform:
    platform_destroy_enclave(&enclaves[eid]);
unset_region:
    pmp_unset_global(region);
free_shared_region:
    pmp_region_free_atomic(shared_region);
free_region:
    pmp_region_free_atomic(region);
free_encl_idx:
    encl_free_eid(eid);
error:
    return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid) {
    int destroyable;

    spin_lock(&encl_lock);
    destroyable = (ENCLAVE_EXISTS(eid) && enclaves[eid].state <= STOPPED);
    /* update the enclave state first so that
     * no SM can run the enclave any longer */
    if (destroyable)
        enclaves[eid].state = DESTROYING;
    spin_unlock(&encl_lock);

    if (!destroyable)
        return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;

    // 0. Let the platform specifics do cleanup/modifications
    platform_destroy_enclave(&enclaves[eid]);

    // 1. clear all the data in the enclave pages
    // requires no lock (single runner)
    int i;
    void *base;
    size_t size;
    region_id rid;
    for (i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
        if (enclaves[eid].regions[i].type == REGION_INVALID ||
            enclaves[eid].regions[i].type == REGION_UTM)
            continue;
        // 1.a Clear all pages
        rid = enclaves[eid].regions[i].pmp_rid;
        base = (void *)pmp_region_get_addr(rid);
        size = (size_t)pmp_region_get_size(rid);
        sbi_memset((void *)base, 0, size);

        // 1.b free pmp region
        pmp_unset_global(rid);
        pmp_region_free_atomic(rid);
    }

    // 2. free pmp region for UTM
    rid = get_enclave_region_index(eid, REGION_UTM);
    if (rid != -1)
        pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

    enclaves[eid].encl_satp = 0;
    enclaves[eid].n_thread = 0;
    enclaves[eid].params = (struct runtime_params_t){0};
    for (i = 0; i < ENCLAVE_REGIONS_MAX; i++) {
        enclaves[eid].regions[i].type = REGION_INVALID;
    }

    // 3. release eid
    encl_free_eid(eid);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid) {
    int runable;

    spin_lock(&encl_lock);
    runable = (ENCLAVE_EXISTS(eid) && enclaves[eid].state == FRESH);
    if (runable) {
        enclaves[eid].state = RUNNING;
        enclaves[eid].n_thread++;
    }
    spin_unlock(&encl_lock);

    if (!runable) {
        return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
    }

    // Enclave is OK to run, context switch to it
    context_switch_to_enclave(regs, eid, 1);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid) {
    int exitable;

    spin_lock(&encl_lock);
    exitable = enclaves[eid].state == RUNNING;
    if (exitable) {
        enclaves[eid].n_thread--;
        if (enclaves[eid].n_thread == 0)
            enclaves[eid].state = STOPPED;
    }
    spin_unlock(&encl_lock);

    if (!exitable)
        return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

    context_switch_to_host(regs, eid, 0);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid) {
    int stoppable;

    spin_lock(&encl_lock);
    stoppable = enclaves[eid].state == RUNNING;
    if (stoppable) {
        // Save enclave's updated satp for runtime attestation
        /* The satp register is updated during the Eyrie boot process
           to refer to the Runtime's page table. If an attestation
           request is received, we have to be in the host's context,
           so the satp will be already updated */
        enclaves[eid].encl_satp = csr_read(satp);

        enclaves[eid].n_thread--;
        if (enclaves[eid].n_thread == 0)
            enclaves[eid].state = STOPPED;
    }
    spin_unlock(&encl_lock);

    if (!stoppable)
        return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

    context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

    switch (request) {
        case (STOP_TIMER_INTERRUPT):
            return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
        case (STOP_EDGE_CALL_HOST):
            return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
        default:
            return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid) {
    int resumable;

    spin_lock(&encl_lock);
    resumable = (ENCLAVE_EXISTS(eid) && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED) && enclaves[eid].n_thread < MAX_ENCL_THREADS);

    if (!resumable) {
        spin_unlock(&encl_lock);
        return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    } else {
        enclaves[eid].n_thread++;
        enclaves[eid].state = RUNNING;
    }
    spin_unlock(&encl_lock);

    // Enclave is OK to resume, context switch to it
    context_switch_to_enclave(regs, eid, 0);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid) {
    int attestable;
    struct report report;
    int ret;

    if (size > ATTEST_DATA_MAXLEN)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

#if PRINT_TICKS
    unsigned long time_start, time_end;
    time_start = sbi_timer_value();
#endif

    spin_lock(&encl_lock);
    attestable = (ENCLAVE_EXISTS(eid) && (enclaves[eid].state >= FRESH));

    if (!attestable) {
        ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
        goto err_unlock;
    }

    /* copy data to be signed */
    ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
                            data, size);
    report.enclave.data_len = size;

    if (ret) {
        ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
        goto err_unlock;
    }

    spin_unlock(&encl_lock);  // Don't need to wait while signing, which might take some time

    sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
    sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
    sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
    sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
    sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
    sm_sign(report.enclave.signature,
            &report.enclave,
            sizeof(struct enclave_report) - SIGNATURE_SIZE - ATTEST_DATA_MAXLEN + size);

    spin_lock(&encl_lock);

    /* copy report to the enclave */
    ret = copy_enclave_report(&enclaves[eid],
                              report_ptr,
                              &report);

    if (ret) {
        ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
        goto err_unlock;
    }

    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

 #if PRINT_TICKS
    time_end = sbi_timer_value();
    sbi_printf("[SM] Time elapsed for creating boot-time report: %lu ticks\n", time_end - time_start);
#endif

err_unlock:
    spin_unlock(&encl_lock);
    return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                              size_t key_ident_size, enclave_id eid) {
    struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
    int ret;

    /* derive key */
    ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                                (const unsigned char *)key_ident, key_ident_size,
                                (const unsigned char *)enclaves[eid].hash);
    if (ret)
        return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

    /* sign derived key */
    sm_sign((void *)key_struct->signature, (void *)key_struct->key,
            SEALING_KEY_SIZE);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long runtime_attestation(struct runtime_report *report) {
    int eid, ret = 0;
    unsigned char sign_buffer[MDSIZE + NONCE_LEN];

#if PRINT_TICKS
    unsigned long time_start, time_end;
    time_start = sbi_timer_value();
#endif

    spin_lock(&encl_lock);

    eid = get_enclave_id_by_uuid(report->enclave.uuid);

    if (eid < 0) {
        sbi_printf("[SM] Enclave not found\n");
        ret = SBI_ERR_SM_ENCLAVE_INVALID_ID;
        goto err_unlock;
    }

    if (enclaves[eid].state != RUNNING && enclaves[eid].state != STOPPED) {
        sbi_printf("[SM] Enclave not measured: it must be in STOPPED or RUNNING state\n");
        sbi_memset(report->enclave.hash, 0, MDSIZE);
        ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
        goto err_unlock;
    }

    sbi_printf("[SM] Enclave %d is being measured... ", eid);

    if (compute_enclave_runtime_hash(&enclaves[eid]) < 0) {
        sbi_printf("[SM] Error while computing the runtime hash\n");
        sbi_memset(report->enclave.hash, 0, MDSIZE);
        goto err_unlock;
    }

    sbi_strncpy((char *)report->enclave.uuid, (const char *)enclaves[eid].uuid, UUID_LEN);
    sbi_memcpy(report->enclave.hash, enclaves[eid].runtime_hash, MDSIZE);

    // Copy hash and nonce to temp buffer (hash || nonce)
    sbi_memcpy(sign_buffer, enclaves[eid].runtime_hash, MDSIZE);
    sbi_memcpy(sign_buffer + MDSIZE, report->nonce, NONCE_LEN);
    ed25519_sign(report->enclave.signature, sign_buffer, MDSIZE + NONCE_LEN, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);

    sbi_memcpy(report->dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
    sbi_memcpy(report->sm.hash, sm_hash, MDSIZE);
    sbi_memcpy(report->sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
    sbi_memcpy(report->sm.signature, sm_signature, SIGNATURE_SIZE);

    if (ret) {
        ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
        goto err_unlock;
    }

    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

    sbi_printf("Operation completed\n");

 #if PRINT_TICKS
    time_end = sbi_timer_value();
    sbi_printf("[SM] Time elapsed for creating run-time report: %lu ticks\n", time_end - time_start);
#endif

err_unlock:
    spin_unlock(&encl_lock);

    return ret;
}

unsigned long get_dice_cert_chain(struct dice_attestation_cert_chain *cert_chain) {
    // Retrieve the enclave ID from the arguments
    enclave_id eid = get_enclave_id_by_uuid(cert_chain->uuid);

    if (!ENCLAVE_EXISTS(eid)) {
        sbi_printf("[SM] Error: Enclave %d does not exist\n", eid);
        return SBI_ERR_SM_ENCLAVE_INVALID_ID;
    }

    // Extract the DER format of the LAK certificate
    unsigned char lak_cert_der[MAX_CERT_LEN];
    int ret, dif, effe_len_cert_der = 0;

    ret = mbedtls_x509write_crt_der(&enclaves[eid].crt_local_att, lak_cert_der, MAX_CERT_LEN, NULL, NULL);
    if (ret > 0) {
        effe_len_cert_der = ret;
    } else
        return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

    unsigned char *cert_real;
    cert_real = lak_cert_der;
    dif = MAX_CERT_LEN - effe_len_cert_der;
    cert_real += dif;

    sbi_memcpy(cert_chain->certs[0], man_cert, man_cert_len);
    sbi_memcpy(cert_chain->certs[1], dev_cert, dev_cert_len);
    sbi_memcpy(cert_chain->certs[2], sm_cert, sm_cert_len);
    sbi_memcpy(cert_chain->certs[3], cert_real, effe_len_cert_der);

    cert_chain->certs_len[0] = man_cert_len;
    cert_chain->certs_len[1] = dev_cert_len;
    cert_chain->certs_len[2] = sm_cert_len;
    cert_chain->certs_len[3] = effe_len_cert_der;

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}