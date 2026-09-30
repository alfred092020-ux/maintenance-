import {describe,expect,it} from 'vitest';import {OutcomeHistory,completionEligible,minimumBlockerCut,reconcileRuntime,stageReceipt,staleStage,validateBudget} from '../../src/core/controlLoop.js';
const obs={projectId:'p',expectedSha:'a',observedSha:'a',servicesHealthy:true,schedulerHealthy:true,verificationHealthy:true,integrationHealthy:true,leasesSane:true,claimsSane:true};
describe('generic nexus control loop',()=>{
 it('requires exactly one integration writer',()=>expect(validateBudget({workerSlots:10,cpu:8,memoryGb:16,heavyE2eSlots:3,deviceSlots:1,integrationWriters:1})).toBe(true));
 it('computes the minimum actionable blocker frontier',()=>expect(minimumBlockerCut('victory',{victory:['battle'],battle:['encounter'],encounter:['field'],field:[]},new Set(['field']))).toEqual(['encounter']));
 it('reconciles runtime truth fail closed',()=>{expect(reconcileRuntime(obs).ok).toBe(true);expect(reconcileRuntime({...obs,observedSha:'b'}).mismatches).toEqual(['runtime-sha'])});
 it('distinguishes productive long work from stale work by heartbeat and expectation',()=>{const r=stageReceipt('e2e','a',5000,1000);expect(staleStage(r,9000)).toBe(false);expect(staleStage(r,12000)).toBe(true)});
 it('learns transparent outcome statistics',()=>{const h=new OutcomeHistory();h.record('patch',true,10);h.record('patch',false,30);expect(h.stats('patch')).toEqual({attempts:2,successRate:.5,meanDurationMs:20})});
 it('requires observed runtime success for completion',()=>{expect(completionEligible(obs,true,true)).toBe(true);expect(completionEligible({...obs,servicesHealthy:false},true,true)).toBe(false)});
});
