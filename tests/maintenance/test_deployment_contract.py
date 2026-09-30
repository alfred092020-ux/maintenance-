import pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class T(unittest.TestCase):
 def test_promoter_accepts_all_maintenance_runtime_files(self):
  s=(ROOT/'scripts/nexus-runtime-promote.sh').read_text()
  for f in ['maintenance/transaction.py','maintenance/certify.py','maintenance/break_glass.sh']:
   self.assertIn(f,s)
 def test_post_promote_rolls_back_unit_and_policy(self):
  s=(ROOT/'scripts/nexus-runtime-post-promote.sh').read_text();self.assertIn('UNIT_BACKUP',s);self.assertIn('install -o root -g root -m 0644 "$UNIT_BACKUP"',s);self.assertIn('POLICY_BACKUP',s)
 def test_tunnel_retains_strict_system_protection_and_only_worker_write_path(self):
  s=(ROOT/'deploy/systemd/nexus-tunnel@.service').read_text();self.assertIn('ProtectSystem=strict',s);self.assertIn('/home/%i/logres/work',s);self.assertNotIn('/home/%i/logres/staging',s)
if __name__=='__main__':unittest.main()
