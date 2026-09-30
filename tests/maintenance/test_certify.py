import json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];CLI=ROOT/'maintenance/certify.py'
class T(unittest.TestCase):
 def test_fail_closed_then_pass(self):
  with tempfile.TemporaryDirectory() as x:
   m=Path(x)/'m';m.write_text(json.dumps({'candidate_sha':'a'}));health=json.dumps({k:True for k in ['servicesHealthy','leasesSane','claimsSane','schedulerHealthy','workerRegistryCompatible','schemasCurrent','verificationAuthorityHealthy','integrationAuthorityHealthy']});base=['python3',str(CLI),'--manifest',str(m),'--source-sha','a','--config-sha','a','--deployed-sha','a','--brain-sha','a','--health-json',health];self.assertEqual(0,subprocess.run(base).returncode);bad=base.copy();bad[bad.index('--deployed-sha')+1]='b';self.assertNotEqual(0,subprocess.run(bad).returncode)
if __name__=='__main__':unittest.main()
