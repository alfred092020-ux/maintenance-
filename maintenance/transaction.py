#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,tempfile,time
TERMINAL={'COMMITTED','ROLLED_BACK'}
def digest(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def write(p,d):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);fd,t=tempfile.mkstemp(prefix='.'+p.name+'.',dir=p.parent)
 try:
  with os.fdopen(fd,'w') as f:json.dump(d,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
  os.replace(t,p)
 finally:
  if os.path.exists(t):os.unlink(t)
def load(p):
 with open(p) as f:return json.load(f)
def prepare(a):
 if pathlib.Path(a.manifest).exists():raise SystemExit('manifest already exists')
 m={'maintenance_id':a.id,'state':'PREPARED','previous_runtime_sha':a.previous_runtime_sha,'candidate_sha':a.candidate_sha,'final_runtime_sha':None,'archive_sha256':digest(a.archive),'config_version':a.config_version,'schema_version':a.schema_version,'migration_version':a.migration_version,'changed_components':a.changed_component,'test_certificate':a.test_certificate,'verification_certificate':a.verification_certificate,'deployment_timestamp':None,'health_check_results':None,'rollback_sha':a.previous_runtime_sha,'reconciliation_result':None,'operator':a.operator,'reason':a.reason,'history':[{'state':'PREPARED','epoch':time.time()}]};write(a.manifest,m)
def transition(a):
 m=load(a.manifest);old=m['state'];new=a.state;allowed={'PREPARED':{'PROMOTING','ROLLED_BACK'},'PROMOTING':{'VALIDATING','ROLLED_BACK'},'VALIDATING':{'COMMITTED','ROLLED_BACK'},'COMMITTED':set(),'ROLLED_BACK':set()}
 if new not in allowed.get(old,set()):raise SystemExit(f'illegal transition {old}->{new}')
 m['state']=new;m['history'].append({'state':new,'epoch':time.time()})
 if a.final_runtime_sha:m['final_runtime_sha']=a.final_runtime_sha
 if a.health:m['health_check_results']=json.loads(a.health)
 if a.reconciliation:m['reconciliation_result']=json.loads(a.reconciliation)
 if new in TERMINAL:m['deployment_timestamp']=time.time()
 write(a.manifest,m)
def recover(a):
 m=load(a.manifest);print('NO_ACTION' if m['state'] in TERMINAL or m['state']=='PREPARED' else f"ROLLBACK_REQUIRED {m['rollback_sha']}")
p=argparse.ArgumentParser();s=p.add_subparsers(dest='cmd',required=True)
q=s.add_parser('prepare');q.add_argument('--manifest',required=True);q.add_argument('--id',required=True);q.add_argument('--archive',required=True);q.add_argument('--previous-runtime-sha',required=True);q.add_argument('--candidate-sha',required=True);q.add_argument('--config-version',default='1');q.add_argument('--schema-version',default='1');q.add_argument('--migration-version',default='1');q.add_argument('--changed-component',action='append',default=[]);q.add_argument('--test-certificate');q.add_argument('--verification-certificate');q.add_argument('--operator',required=True);q.add_argument('--reason',required=True);q.set_defaults(fn=prepare)
q=s.add_parser('transition');q.add_argument('--manifest',required=True);q.add_argument('--state',required=True,choices=['PREPARED','PROMOTING','VALIDATING','COMMITTED','ROLLED_BACK']);q.add_argument('--final-runtime-sha');q.add_argument('--health');q.add_argument('--reconciliation');q.set_defaults(fn=transition)
q=s.add_parser('recover');q.add_argument('--manifest',required=True);q.set_defaults(fn=recover)
a=p.parse_args();a.fn(a)
