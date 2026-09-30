import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadCapabilityPolicy } from '../../src/privileged/capabilityPolicy.js';
import { evaluatePrivilegeRequest } from '../../src/privileged/decision.js';
import { NonceTracker, signPrivilegedRequest, verifyPrivilegedRequest } from '../../src/privileged/protocol.js';

function policy(capability: Record<string, unknown>) {
  const dir = mkdtempSync(path.join(tmpdir(), 'nexus-policy-'));
  const file = path.join(dir, 'policy.json');
  writeFileSync(file, JSON.stringify({schemaVersion:1,policyVersion:'test',bundles:[{id:'maintenance',capabilities:[capability]}]}));
  return loadCapabilityPolicy(file, 1000);
}

describe('maintenance governance authority', () => {
  it('accepts exactly one maintenance authority for GOVERNED capability', () => {
    const loaded = policy({id:'nexus.maintenance.promote',operation:'deployment.nexusMaintenancePromoteVerified',riskClass:'GOVERNED',requiredMachineCapability:'HOST_PERMISSIONS',requireMaintenanceTransaction:true});
    const result = evaluatePrivilegeRequest(loaded,{machineId:'m',operation:'deployment.nexusMaintenancePromoteVerified',payload:{},now:1000},{machineCapabilities:new Set(['HOST_PERMISSIONS']),logresLease:null,maintenanceTransaction:{transactionId:'M-1',reason:'upgrade',expiresAt:2000}});
    expect(result.allowed).toBe(true);
  });

  it('fails closed without a maintenance transaction', () => {
    const loaded = policy({id:'nexus.maintenance.promote',operation:'deployment.nexusMaintenancePromoteVerified',riskClass:'GOVERNED',requiredMachineCapability:'HOST_PERMISSIONS',requireMaintenanceTransaction:true});
    const result = evaluatePrivilegeRequest(loaded,{machineId:'m',operation:'deployment.nexusMaintenancePromoteVerified',payload:{},now:1000},{machineCapabilities:new Set(['HOST_PERMISSIONS']),logresLease:null,maintenanceTransaction:null});
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/maintenance transaction/);
  });

  it('rejects ambiguous dual governance authority', () => {
    expect(() => policy({id:'bad',operation:'deployment.nexusMaintenancePromoteVerified',riskClass:'GOVERNED',requiredMachineCapability:'HOST_PERMISSIONS',requireLogresLease:true,requireMaintenanceTransaction:true})).toThrow(/exactly one governance authority/);
  });


  it('rejects an expired maintenance transaction', () => {
    const loaded = policy({id:'nexus.maintenance.promote',operation:'deployment.nexusMaintenancePromoteVerified',riskClass:'GOVERNED',requiredMachineCapability:'HOST_PERMISSIONS',requireMaintenanceTransaction:true});
    const result = evaluatePrivilegeRequest(loaded,{machineId:'m',operation:'deployment.nexusMaintenancePromoteVerified',payload:{},now:2000},{machineCapabilities:new Set(['HOST_PERMISSIONS']),logresLease:null,maintenanceTransaction:{transactionId:'M-1',reason:'upgrade',expiresAt:1999}});
    expect(result.allowed).toBe(false);
  });

  it('cryptographically binds maintenance context into the signed envelope', () => {
    const key = Buffer.alloc(32, 7);
    const signed = signPrivilegedRequest({machineId:'m',operation:'service.nexusMaintenanceManage',payload:{name:'nexus-agent.service',action:'status'},maintenanceContext:{transactionId:'M-1',reason:'health check',expiresAt:2000},timestamp:1000},key);
    const verified = verifyPrivilegedRequest(signed,key,new NonceTracker(),1000);
    expect(verified.maintenanceContext?.transactionId).toBe('M-1');
    const tampered = {...signed,maintenanceContext:{transactionId:'M-2',reason:'health check',expiresAt:2000}};
    expect(() => verifyPrivilegedRequest(tampered,key,new NonceTracker(),1000)).toThrow(/invalid signature/);
  });
});
