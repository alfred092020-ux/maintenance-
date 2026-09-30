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
if __name__=='__main__':unittest.main()
