import json,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class T(unittest.TestCase):
 def test_nexus_mutation_has_one_external_authority(self):
  p=json.loads((ROOT/'deploy/privileged-policy.json').read_text());caps=[(b['id'],c) for b in p['bundles'] for c in b['capabilities'] if c['operation'] in {'service.nexusManage','deployment.nexusInstallVerified','deployment.nexusPromoteVerified','service.nexusMaintenanceManage','deployment.nexusMaintenanceInstallVerified','deployment.nexusMaintenancePromoteVerified'}];self.assertTrue(caps);self.assertEqual({'nexus-external-maintenance'},{b for b,_ in caps});self.assertTrue(all(c.get('requireMaintenanceTransaction') is True for _,c in caps));self.assertTrue(all('requireLogresLease' not in c for _,c in caps))
 def test_legacy_admin_is_human_only(self):
  p=json.loads((ROOT/'deploy/privileged-policy.json').read_text());legacy=next(b for b in p['bundles'] if b['id']=='legacy-admin');self.assertTrue(all(c['riskClass']=='HUMAN_ONLY' for c in legacy['capabilities']))
if __name__=='__main__':unittest.main()
