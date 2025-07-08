//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create_t create_args_local;
  unsigned long ret;

  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret)
    return ret;

  ret = create_enclave(eid, create_args_local);
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
  unsigned long ret;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  regs->a0 = run_enclave(regs, (unsigned int) eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero)
    regs->a0 = ret;
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
  regs->a0 = exit_enclave(regs, cpu_get_enclave_id());
  regs->a1 = retval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  regs->a0 = stop_enclave(regs, request, cpu_get_enclave_id());
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                       size_t key_ident_size)
{
  unsigned long ret;
  ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
                         cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_random(void)
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}

unsigned long sbi_sm_runtime_attestation(uintptr_t report) {
  struct runtime_report report_local;
  
  unsigned long ret = copy_runtime_attestation_report_into_sm(report, &report_local);  
  if (ret) {
    sbi_printf("[SM] Error while copying runtime attestation report\n");
    return ret;
  }
  
  ret = runtime_attestation(&report_local);
  if (ret)
    return ret;

  ret = copy_runtime_attestation_report_from_sm(&report_local, report);
  if (ret)
    sbi_printf("[SM] Error while copying runtime attestation report\n");

  return ret;
}


// unsigned long sbi_sm_get_lak_cert(uintptr_t args) {
//   struct lak_cert_args local_args;
//   unsigned long ret;

//   // Retrieve LAK cert from the SM
//   if (copy_to_sm(&local_args, args, sizeof(struct lak_cert_args)))
//     return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  
//   ret = get_cert(local_args.uuid, local_args.cert_lak, &(local_args.cert_len), CERT_LAK);
//   if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
//     return ret;

//   // Copy cert data back to user space
//   if (copy_from_sm(args, &local_args, sizeof(struct lak_cert_args)))
//     return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

//   return ret;
// }

