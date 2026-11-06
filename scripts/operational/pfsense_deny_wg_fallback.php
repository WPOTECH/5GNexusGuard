<?php
/* Explicit disposable-copy correction only. Never run against an original VM. */
$actual_uuid=strtolower(trim(shell_exec('/bin/kenv -q smbios.system.uuid')));
if ($argc!==2 || !preg_match('/^[0-9a-f-]{36}$/D',$argv[1]) || $actual_uuid!==$argv[1]
    || trim(file_get_contents('/etc/version'))!=='2.7.2-RELEASE'
    || strpos(shell_exec('/sbin/ifconfig vtnet0'),'ether 52:54:00:23:01:01')===false
    || strpos(shell_exec('/sbin/ifconfig vtnet1'),'ether 52:54:00:23:01:02')===false) {
    throw new Exception('explicit disposable UUID and test NIC/config identities required');
}
require_once('config.inc');require_once('functions.inc');require_once('filter.inc');
require_once('shaper.inc');require_once('ipsec.inc');require_once('vpn.inc');
if (($config['interfaces']['wan']['if']??'')!=='vtnet0'
    || ($config['interfaces']['lan']['if']??'')!=='vtnet1'
    || ($config['interfaces']['wan']['descr']??'')!=='P23_TEST_WAN') {
    throw new Exception('explicit disposable interface configuration required');
}
$rules=[];
foreach ($config['filter']['rule'] as $rule) {
    if (($rule['protocol']??'')==='udp' && ($rule['destination']['port']??'')==='51821'
        && in_array($rule['source']['address']??'', ['10.77.0.1','10.78.0.2'],true)
        && in_array($rule['destination']['address']??'', ['10.77.0.1','10.78.0.2'],true)) {
        if (strpos($rule['descr']??'','P23')!==0) throw new Exception('foreign transport rule');
        continue;
    }
    $rules[]=$rule;
}
function wg_rule($type,$iface,$direction,$src,$dst,$label) {
    return ['type'=>$type,'floating'=>'yes','quick'=>'yes','direction'=>$direction,
      'interface'=>$iface,'ipprotocol'=>'inet','protocol'=>'udp',
      'source'=>['address'=>$src,'port'=>'51821'],
      'destination'=>['address'=>$dst,'port'=>'51821'],
      'statetype'=>'none','descr'=>$label,
      'tracker'=>strval(random_int(1000000000,1999999999))];
}
$rules[]=wg_rule('block','wan','out','10.78.0.2','10.77.0.1','P23 deny outer plaintext WG fallback');
$rules[]=wg_rule('pass','lan,enc0','any','10.77.0.1','10.78.0.2','P23 stateless WG endpoint to inner');
$rules[]=wg_rule('pass','lan,enc0','any','10.78.0.2','10.77.0.1','P23 stateless WG inner to endpoint');
$config['filter']['rule']=$rules;
write_config('P23 deny clear WireGuard WAN fallback; stateless exact inner transport');
$result=filter_configure_sync(false);
if ($result!==0) throw new Exception('filter reload failed: '.json_encode($result));
echo "P23_FALLBACK_DENIAL_CONFIGURED\n";
