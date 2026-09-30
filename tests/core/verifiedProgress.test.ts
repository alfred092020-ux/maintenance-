import {describe,expect,it} from 'vitest';
import {authorityChain,decide,failureFingerprint,operatorIntentWins,retryDecision,riskPlan,speculativeReceiptValid} from '../../src/core/verifiedProgress.js';
describe('verified progress core',()=>{
 it('ranks EVP inside hard priority',()=>{const x=decide([{id:'a',priority:0,unlockValue:1,successLikelihood:1,verificationConfidence:1,expectedMinutes:10,resourceCost:1,capability:'code',claimedState:'READY',observedState:'READY'},{id:'b',priority:0,unlockValue:5,successLikelihood:1,verificationConfidence:1,expectedMinutes:10,resourceCost:1,capability:'code',claimedState:'READY',observedState:'READY'}]);expect(x[0]!.id).toBe('b')});
 it('fails reconciliation closed',()=>expect(decide([{id:'a',priority:0,unlockValue:9,successLikelihood:1,verificationConfidence:1,expectedMinutes:1,resourceCost:1,capability:'code',claimedState:'ACTIVE',observedState:'ABSENT'}])[0]!.eligible).toBe(false));
 it('uses risk aware adaptive QA',()=>{expect(riskPlan(['src/privileged/main.ts']).lanes).toContain('e2e');expect(riskPlan(['docs/x.md']).lanes).not.toContain('e2e');expect(riskPlan(['src/jobs/x.ts'],8,8,.1).heavySlots).toBe(1)});
 it('never blindly repeats same failure',()=>{const f=failureFingerprint('t','s','e','boom');expect(retryDecision(new Set([f]),'t','s','e','boom',true).retry).toBe(false)});
 it('reuses speculative receipts only when independent and unaffected',()=>{expect(speculativeReceiptValid({baseSha:'a',paths:['docs/a'],independent:true},'b',['src/x'])).toBe(true);expect(speculativeReceiptValid({baseSha:'a',paths:['src/x'],independent:true},'b',['src/x'])).toBe(false)});
 it('requires four independent authorities',()=>{expect(authorityChain('b','v','i','o').eligible).toBe(true);expect(authorityChain('b','b','i','o').eligible).toBe(false)});
 it('new operator intent dominates old',()=>{expect(operatorIntentWins(20,10)).toBe(false);expect(operatorIntentWins(20,21)).toBe(true)});
});
