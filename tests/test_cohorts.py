"""Stdlib-only tests for the anonymous on-chain implementation cohort analysis."""
import csv
import tempfile
import unittest
from pathlib import Path

from msfp.cohorts import analyze, write_outputs

K1='03' + '11'*32
K2='02' + '22'*32
K3='03' + '33'*32
K4='02' + '44'*32
K5='02' + '55'*32
K6='02' + '66'*32


class CohortTests(unittest.TestCase):
    def _write(self, path, cols, rows):
        with path.open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=cols)
            writer.writeheader()
            writer.writerows(rows)

    def fixture(self, folder):
        graph=Path(folder)
        script_rows=[]; edges=[]
        # 8 distinct 2/3 scripts sharing a single constant institutional
        # cosigning key at index 1; unique partner keys vary per script.
        for i in range(8):
            sha=f'{i:064x}'
            keya='02'+f'{i+1:064x}'
            keyb='03'+f'{i+100:064x}'
            script_rows.append({'script_sha256':sha,'source':'p2wsh_witness',
                'script_class':'multisig','family_l4':'standard_multisig',
                'template_l3':'OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG',
                'threshold':'2','n_keys':'3','keys_sorted':'0',
                'first_seen_height':str(900000+i),'last_seen_height':str(900000+i),
                'n_observations':'1'})
            for pos,key in enumerate([keya,K1,keyb]):
                edges.append({'script_sha256':sha,'pubkey_hex':key,'position':str(pos)})
        # An unrelated 2/2 script sharing K1 is NOT joined to the 2/3 cohort.
        sha=f'{100:064x}'
        script_rows.append({'script_sha256':sha,'source':'p2wsh_witness',
            'script_class':'multisig','family_l4':'standard_multisig',
            'template_l3':'OP_2 <P> <P> OP_2 OP_CHECKMULTISIG',
            'threshold':'2','n_keys':'2','keys_sorted':'1',
            'first_seen_height':'900000','last_seen_height':'900000',
            'n_observations':'1'})
        for pos,key in enumerate([K1,K2]):
            edges.append({'script_sha256':sha,'pubkey_hex':key,'position':str(pos)})
        self._write(graph/'nodes_script.csv',list(script_rows[0]),script_rows)
        self._write(graph/'edges_key_in_script.csv',list(edges[0]),edges)
        return graph

    def test_exact_hub_without_false_provider_attribution(self):
        with tempfile.TemporaryDirectory() as temp:
            graph=self.fixture(temp)
            data,members=analyze(graph,5)
            self.assertEqual(data['n_standard_multisig_scripts'],9)
            self.assertEqual(data['n_anonymous_key_cohorts'],1)
            cohort=data['key_cohorts'][0]
            self.assertEqual(cohort['n_distinct_scripts'],8)
            self.assertEqual(cohort['anchor_positions'],{1:8})
            self.assertEqual(cohort['threshold'],2)
            self.assertEqual(cohort['n_keys'],3)
            self.assertEqual(len(members),8)
            self.assertFalse('provider' in cohort)
            out=write_outputs(data,members,Path(temp)/'out')
            self.assertTrue((out/'anonymous_cohorts.md').exists())

    def test_fully_co_recurring_keys_are_one_cohort(self):
        with tempfile.TemporaryDirectory() as temp:
            rows=[]; edges=[]
            fixed=[K1,K2,K3]
            for i in range(9):
                sha=f'{500+i:064x}'
                rows.append({'script_sha256':sha,'source':'p2sh_redeem',
                    'script_class':'multisig','family_l4':'standard_multisig',
                    'template_l3':'OP_3 <P> <P> <P> <P> OP_4 OP_CHECKMULTISIG',
                    'threshold':'3','n_keys':'4','keys_sorted':'0',
                    'first_seen_height':str(900000+i),'last_seen_height':str(900000+i),
                    'n_observations':'1'})
                for pos,key in enumerate(fixed+['02'+f'{i+900:064x}']):
                    edges.append({'script_sha256':sha,'pubkey_hex':key,'position':str(pos)})
            self._write(Path(temp)/'nodes_script.csv',list(rows[0]),rows)
            self._write(Path(temp)/'edges_key_in_script.csv',list(edges[0]),edges)
            data,_=analyze(temp,5)
            self.assertEqual(len(data['key_cohorts']),1)
            a=data['key_cohorts'][0]
            self.assertEqual(a['n_distinct_scripts'],9)
            self.assertEqual(a['n_jointly_shared_scripts'],9)
            self.assertEqual(len(a['co_recurring_keys']),3)

    def test_min_shared_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            graph=self.fixture(temp)
            data,_=analyze(graph,9)
            self.assertEqual(data['n_anonymous_key_cohorts'],0)


if __name__=='__main__':
    unittest.main()
