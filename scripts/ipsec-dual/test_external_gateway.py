"""External adapter fails closed on foreign NICs, dead daemons and stale transport."""
import copy
import unittest
from unittest.mock import patch
from external_gateway import interfaces,ExternalHealth,ExternalTopology

class ExternalTests(unittest.TestCase):
    def test_exact_operator_nics_or_post_move_loopback_only(self):
        cfg={r:dict(name='p23-'+r,mac='52:54:00:23:02:0'+str(i)) for i,r in enumerate(('wan','lan'),1)}
        lo=dict(ifname='lo',address='00:00:00:00:00:00')
        rows=[lo]+[dict(ifname=x['name'],address=x['mac']) for x in cfg.values()]
        self.assertEqual(interfaces(cfg,rows),cfg)
        self.assertEqual(interfaces(cfg,[lo]),cfg)
        for bad in (rows+[dict(ifname='eth9')],rows[:2],[],[dict(ifname='lo'),dict(ifname='p23-wan',address='other')]):
            with self.assertRaises(ValueError):interfaces(cfg,bad)
        bad=copy.deepcopy(cfg);bad['lan']['mac']=bad['wan']['mac']
        with self.assertRaises(ValueError):interfaces(bad,rows)

    def test_fresh_echo_requires_both_esp_directions_and_same_session(self):
        health=ExternalHealth.__new__(ExternalHealth);health.endpoint_ns='e'
        health.run=lambda args: '32 bytes from 10.79.0.2: icmp_seq=1\n1 packets transmitted, 1 received\n'
        for after,want in (((('sa',),(11,21)),True),((('sa',),(11,20)),False),((('new',),(11,21)),False),(None,False)):
            with patch.object(health,'_snapshot',side_effect=[(('sa',),(10,20)),after]):
                self.assertEqual(health._challenge(),want)
        with patch.object(health,'_identities',return_value=False):self.assertIsNone(health._snapshot())

    def test_child_selectors_and_both_spis_are_bound_to_exact_sa(self):
        import json
        h=ExternalHealth.__new__(ExternalHealth);h.endpoint_ns='e';h.inner_ns='i';h.wg='wg-inner'
        from pathlib import Path
        h.vici_dir=Path('/private')
        good=('hybrid: #1, ESTABLISHED, IKEv2, 1111111111111111_i* 2222222222222222_r\n'
              '  inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP:AES_GCM_16-256\n'
              '    in  12345678, 10 bytes\n    out 87654321, 10 bytes\n'
              '    local  10.77.0.1/32[udp/51821]\n    remote 10.78.0.2/32[udp/51821]\n')
        raw=''.join('src '+src+' dst '+dst+'\n    proto esp spi 0x'+spi+'(1) reqid 42(0x0000002a) mode tunnel\n    lifetime current:\n    10(bytes), 1(packets)\n' for src,dst,spi in [('192.0.2.1','192.0.2.2','87654321'),('192.0.2.2','192.0.2.1','12345678')])
        def run(args):
            if 'route' in args:return json.dumps([{'dev':'wg-inner'}])
            if 'addr' in args:return json.dumps([{'addr_info':[{'family':'inet','local':'10.79.0.1' if args[3]=='e' else '10.79.0.2'}]}])
            return status if 'swanctl' in args else xfrm
        h.run=run
        other=good.replace('inner-transport: #1, reqid 42','other.child: #2, reqid 99').split('\n',1)[1]
        for status,xfrm,want in [(good,raw,True),(good.replace('[udp/51821]','[tcp/51821]')+other,raw,False),(good,raw.replace('0x12345678','0x99999999'),False),(good.replace('    in  12345678, 10 bytes\n    out 87654321, 10 bytes\n','')+other,raw,False)]:
            with patch.object(h,'_identities',return_value=True):self.assertEqual(h._snapshot() is not None,want)

    def test_failed_map_cleanup_remains_uncertain_with_bounded_diagnostics(self):
        from kernel_gate_publisher_v2 import Publisher
        publisher=Publisher.__new__(Publisher);publisher.health_path='health';publisher.auth_path='auth'
        with patch.object(publisher,'_update',side_effect=[RuntimeError('secret-path-do-not-log'),RuntimeError('Kernel gate command failed: kernel_command_failed exit=-15')]) as update:
            with self.assertRaises(RuntimeError) as caught:publisher.revoke()
        self.assertEqual(update.call_count,2);self.assertTrue(publisher.revocation_uncertain)
        self.assertNotIn('secret-path',str(caught.exception));self.assertIn('exit=-15',str(caught.exception))

    def test_external_routes_do_not_configure_appliance(self):
        topology=ExternalTopology.__new__(ExternalTopology)
        with patch('external_gateway.Topology.route') as route:
            topology.route('o','10.77.0.1/32','via','192.0.2.1');route.assert_not_called()
            topology.route('e','10.78.0.2/32','via','192.0.2.2');route.assert_called_once()

if __name__=='__main__':unittest.main()
