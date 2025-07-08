//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include <crypto.h>
#include "page.h"
#include <sbi/sbi_console.h>
 #if PRINT_TICKS
#include <sbi/sbi_timer.h>
#endif

static inline uintptr_t satp_to_pa(uintptr_t satp) {
  uintptr_t ppn = satp & SATP_PPN;
  return (ppn << RISCV_PGSHIFT);
}

// static void print_hash(byte* hash) {
//   for (int i = 0; i < MDSIZE; i++) {
//       sbi_printf("%02x", hash[i]);
//   }
//   sbi_printf("\n");
// }

/* This will hash the loader and the runtime + eapp elf files. */
static int validate_and_hash_epm(hash_ctx* ctx, struct enclave* encl)
{
  uintptr_t loader = encl->params.dram_base; // also base
  uintptr_t runtime = encl->params.runtime_base;
  uintptr_t eapp = encl->params.user_base;
  uintptr_t free = encl->params.free_base;

  // ensure pointers don't point to middle of correct files
  uintptr_t sizes[3] = {runtime - loader, eapp - runtime, free - eapp};
  hash_extend(ctx, (void*) sizes, sizeof(sizes));

  sbi_printf("[SM] loader: 0x%lx, runtime: 0x%lx, eapp: 0x%lx, free: 0x%lx\n", loader, runtime, eapp, free);

  // using pointers to ensure that they themselves are correct
  // TODO(Evgeny): can extend by entire file instead of page at a time?
  for (uintptr_t page = loader; page < runtime; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
  }
  for (uintptr_t page = runtime; page < eapp; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
  }
  for (uintptr_t page = eapp; page < free; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
  }
  return 0;
}

static int hash_ro_pages(hash_ctx* ctx, struct enclave* encl, pte_t* tb, uintptr_t vaddr, int level) {
  uintptr_t phys_addr, va_start, vpn, utm_ptr;
  int i, executable, va_is_not_utm;

  for (i = 0, va_is_not_utm = 1; i < RISCV_PGSIZE / sizeof(pte_t); i++) {
    uintptr_t pte = tb[i];
    if (!(pte & PTE_V))
      continue;

    if (level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT)
      vpn = ((-1UL << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));
    else
      vpn = ((vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));

    phys_addr = (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

    // if PTE is a leaf
    if (level == 1) {
      va_start      = vpn << RISCV_PGSHIFT;
      utm_ptr       = encl->params.untrusted_base;
      executable    = (pte & PTE_X) && !(pte & PTE_W);
      va_is_not_utm &= !(va_start >= utm_ptr &&
                          va_start < utm_ptr + encl->params.untrusted_size);

      if (va_is_not_utm && executable)
        hash_extend_page(ctx, (void *)phys_addr);
    } else  // otherwise, recurse on a lower level
      hash_ro_pages(ctx, encl, (pte_t *)phys_addr, vpn, level - 1);
  }

  return 0;
}

unsigned long validate_and_hash_enclave(struct enclave* enclave) {
  #if PRINT_TICKS
  unsigned long time_start, time_end;
  time_start = sbi_timer_value();
  #endif

  hash_ctx ctx;
  hash_init(&ctx);

  // TODO: ensure untrusted and free sizes

  // hash the epm contents
  int valid = validate_and_hash_epm(&ctx, enclave);

  if(valid == -1){
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }

  hash_finalize(enclave->hash, &ctx);

   #if PRINT_TICKS
  time_end = sbi_timer_value();
  sbi_printf("\n[SM] Time elapsed for boot-time measurement: %lu ticks\n", time_end - time_start);
  #endif

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long compute_enclave_runtime_hash(struct enclave* enclave) {
  #if PRINT_TICKS
  unsigned long time_start, time_end;
  time_start = sbi_timer_value();
  #endif

  hash_ctx ctx;
  hash_init(&ctx);
  hash_ro_pages(&ctx, enclave, (pte_t *) satp_to_pa(enclave->encl_satp), 0, RISCV_PGLEVEL_TOP);
  hash_finalize(enclave->runtime_hash, &ctx);

   #if PRINT_TICKS
  time_end = sbi_timer_value();
  sbi_printf("\n[SM] Time elapsed for run-time measurement: %lu ticks\n", time_end - time_start);
  #endif

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
