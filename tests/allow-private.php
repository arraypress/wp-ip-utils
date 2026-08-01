<?php
/**
 * IP::get( true ) — permissive addresses, same trust rule.
 */
declare(strict_types=1);
require __DIR__ . '/../src/IP.php';
use ArrayPress\IPUtils\IP;

$pass=0;$fail=0;
function check(string $label, array $server, ?string $expected): void {
    global $pass,$fail;
    $_SERVER = $server;
    $got = IP::get( true );
    if ($got === $expected) { printf("  PASS  %-54s → %s\n",$label,var_export($got,true)); $pass++; }
    else { printf("  FAIL  %-54s got %s, expected %s\n",$label,var_export($got,true),var_export($expected,true)); $fail++; }
}

echo "Permissive mode still refuses untrusted forwarding headers\n";
check('spoofed X-Real-IP ignored from public origin', ['REMOTE_ADDR'=>'8.8.8.8','HTTP_X_REAL_IP'=>'1.2.3.4'], '8.8.8.8');
check('spoofed CF header ignored from public origin', ['REMOTE_ADDR'=>'8.8.8.8','HTTP_CF_CONNECTING_IP'=>'1.2.3.4'], '8.8.8.8');

echo "\nPermissive mode captures private addresses\n";
check('loopback returned instead of null',            ['REMOTE_ADDR'=>'127.0.0.1'], '127.0.0.1');
check('intranet client via trusted local proxy',      ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'192.168.1.50'], '192.168.1.50');
check('docker link-local',                            ['REMOTE_ADDR'=>'172.17.0.1'], '172.17.0.1');

echo "\nStrict mode unchanged\n";
$_SERVER = ['REMOTE_ADDR'=>'127.0.0.1'];
if (IP::get() === null) { echo "  PASS  strict still returns null for loopback\n"; $pass++; }
else { echo "  FAIL  strict returned ".var_export(IP::get(),true)."\n"; $fail++; }

printf("\n%d passed, %d failed\n",$pass,$fail);
exit($fail?1:0);
