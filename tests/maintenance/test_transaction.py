import json,subprocess,tempfile,unittest
from pathlib import Path
CLI=Path(__file__).resolve().parents[2]/'maintenance/transaction.py'
class T(unittest.TestCase):
 def r(self,*a,ok=True):
  p=subprocess.run(['python3',str(CLI),*a],text=True,capture_output=True)
  if ok:self.assertEqual(0,p.returncode,p.stderr)
  return p
 def prep(self,d,m):
  a=d/'a';a.write_bytes(b'x');self.r('prepare','--manifest',str(m),'--id','M','--archive',str(a),'--previous-runtime-sha','old','--candidate-sha','new','--operator','test','--reason','upgrade')
 def test_commit_chain(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m)
   for s in ['PROMOTING','VALIDATING']:self.r('transition','--manifest',str(m),'--state',s)
   self.r('transition','--manifest',str(m),'--state','COMMITTED','--final-runtime-sha','new','--health','{"ok":true}','--reconciliation','{"ok":true}')
   z=json.loads(m.read_text());self.assertEqual(['PREPARED','PROMOTING','VALIDATING','COMMITTED'],[h['state'] for h in z['history']]);self.assertEqual('old',z['rollback_sha'])
 def test_crash_recovery(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);self.r('transition','--manifest',str(m),'--state','PROMOTING');self.assertIn('ROLLBACK_REQUIRED old',self.r('recover','--manifest',str(m)).stdout)
 def test_illegal_skip_rejected(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);self.assertNotEqual(0,self.r('transition','--manifest',str(m),'--state','COMMITTED',ok=False).returncode)
 def test_rollback_is_terminal(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);self.r('transition','--manifest',str(m),'--state','PROMOTING');self.r('transition','--manifest',str(m),'--state','ROLLED_BACK');self.assertIn('NO_ACTION',self.r('recover','--manifest',str(m)).stdout);self.assertNotEqual(0,self.r('transition','--manifest',str(m),'--state','PROMOTING',ok=False).returncode)
 def test_validating_crash_requires_rollback(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);self.r('transition','--manifest',str(m),'--state','PROMOTING');self.r('transition','--manifest',str(m),'--state','VALIDATING');self.assertIn('ROLLBACK_REQUIRED old',self.r('recover','--manifest',str(m)).stdout)
 def test_archive_tamper_blocks_promotion(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);json.loads(m.read_text());Path(json.loads(m.read_text())['archive_path']).write_bytes(b'tampered');self.assertNotEqual(0,self.r('transition','--manifest',str(m),'--state','PROMOTING',ok=False).returncode);self.assertEqual('PREPARED',json.loads(m.read_text())['state'])
 def test_commit_requires_exact_candidate_sha(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);self.r('transition','--manifest',str(m),'--state','PROMOTING');self.r('transition','--manifest',str(m),'--state','VALIDATING');self.assertNotEqual(0,self.r('transition','--manifest',str(m),'--state','COMMITTED','--final-runtime-sha','wrong',ok=False).returncode)
 def test_concurrent_transition_has_single_winner(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);cmd=['python3',str(CLI),'transition','--manifest',str(m),'--state','PROMOTING'];ps=[subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(8)];results=[p.communicate() for p in ps];codes=[p.returncode for p in ps];self.assertEqual(1,codes.count(0));self.assertEqual('PROMOTING',json.loads(m.read_text())['state'])
 def test_corrupt_manifest_fails_closed(self):
  with tempfile.TemporaryDirectory() as x:
   m=Path(x)/'m';m.write_text('{bad');self.assertNotEqual(0,self.r('recover','--manifest',str(m),ok=False).returncode)
 def test_unknown_state_fails_closed(self):
  with tempfile.TemporaryDirectory() as x:
   d=Path(x);m=d/'m';self.prep(d,m);z=json.loads(m.read_text());z['state']='ALIEN';m.write_text(json.dumps(z));self.assertNotEqual(0,self.r('recover','--manifest',str(m),ok=False).returncode)
if __name__=='__main__':unittest.main()
