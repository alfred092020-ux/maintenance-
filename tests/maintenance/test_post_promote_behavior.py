import pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class T(unittest.TestCase):
 def test_unit_backup_is_defined_before_first_use(self):
  s=(ROOT/'scripts/nexus-runtime-post-promote.sh').read_text();definition=s.index('UNIT_BACKUP=');first_use=s.index('$UNIT_BACKUP');self.assertLess(definition,first_use)
 def test_unit_backup_is_taken_before_install_and_removed_on_success(self):
  s=(ROOT/'scripts/nexus-runtime-post-promote.sh').read_text();backup=s.index('cp -f /etc/systemd/system/nexus-tunnel@.service "$UNIT_BACKUP"');install=s.index('install -o root -g root -m 0644 /opt/nexus-commander/deploy/systemd/nexus-tunnel@.service');cleanup=s.index('rm -f "$UNIT_BACKUP"');self.assertLess(backup,install);self.assertGreater(cleanup,install)
 def test_failure_restores_runtime_policy_and_unit_before_restart(self):
  s=(ROOT/'scripts/nexus-runtime-post-promote.sh').read_text();failure=s.index('if [[ "$healthy" -ne 1 ]]');block=s[failure:];self.assertIn('mv "$PREVIOUS" /opt/nexus-commander',block);self.assertIn('cp -f "$POLICY_BACKUP" "$POLICY"',block);self.assertIn('install -o root -g root -m 0644 "$UNIT_BACKUP"',block);self.assertLess(block.index('install -o root -g root -m 0644 "$UNIT_BACKUP"'),block.index('systemctl daemon-reload'))
if __name__=='__main__':unittest.main()
