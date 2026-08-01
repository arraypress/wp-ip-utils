<?php
declare(strict_types=1);
require __DIR__ . '/../src/IP.php';
use ArrayPress\IPUtils\IP;

$pass=0;$fail=0;
function check(string $label, array $server, ?string $expected): void {
    global $pass,$fail;
    $_SERVER = $server;
    $got = IP::get();
    if ($got === $expected) { printf("  PASS  %-52s → %s\n",$label,var_export($got,true)); $pass++; }
    else { printf("  FAIL  %-52s got %s, expected %s\n",$label,var_export($got,true),var_export($expected,true)); $fail++; }
}

echo "Untrusted origin (attacker reaching the box directly)\n";
check('spoofed CF-Connecting-IP is ignored', ['REMOTE_ADDR'=>'8.8.8.8','HTTP_CF_CONNECTING_IP'=>'1.2.3.4'], '8.8.8.8');
check('spoofed X-Real-IP is ignored',        ['REMOTE_ADDR'=>'8.8.8.8','HTTP_X_REAL_IP'=>'1.2.3.4'], '8.8.8.8');
check('spoofed X-Forwarded-For is ignored',  ['REMOTE_ADDR'=>'8.8.8.8','HTTP_X_FORWARDED_FOR'=>'1.2.3.4'], '8.8.8.8');
check('spoofed Client-IP is ignored',        ['REMOTE_ADDR'=>'8.8.8.8','HTTP_CLIENT_IP'=>'1.2.3.4'], '8.8.8.8');

echo "\nBehind Cloudflare (104.16.0.1 is a CF range)\n";
check('CF-Connecting-IP honoured',           ['REMOTE_ADDR'=>'104.16.0.1','HTTP_CF_CONNECTING_IP'=>'93.184.216.34'], '93.184.216.34');
check('XFF honoured',                        ['REMOTE_ADDR'=>'104.16.0.1','HTTP_X_FORWARDED_FOR'=>'93.184.216.34'], '93.184.216.34');

echo "\nBehind a local proxy (nginx on 127.0.0.1)\n";
check('XFF honoured',                        ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'93.184.216.34'], '93.184.216.34');
check('XFF chain: rightmost untrusted wins', ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'1.2.3.4, 93.184.216.34, 10.0.0.5'], '93.184.216.34');
check('pre-seeded fake hop is skipped',      ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'6.6.6.6, 93.184.216.34'], '93.184.216.34');
check('port is stripped',                    ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'93.184.216.34:51234'], '93.184.216.34');
check('bracketed IPv6 with port',            ['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>'[2001:4860:4860::8888]:443'], '2001:4860:4860::8888');

echo "\nDirect / degenerate\n";
check('direct public connection',            ['REMOTE_ADDR'=>'93.184.216.34'], '93.184.216.34');
check('private only returns null',           ['REMOTE_ADDR'=>'127.0.0.1'], null);
check('no REMOTE_ADDR returns null',         [], null);
check('garbage REMOTE_ADDR returns null',    ['REMOTE_ADDR'=>'not-an-ip'], null);

echo "\nConfiguration\n";
define('ARRAYPRESS_TRUSTED_PROXIES', '');
check('empty trust list ignores all headers',['REMOTE_ADDR'=>'104.16.0.1','HTTP_CF_CONNECTING_IP'=>'1.2.3.4'], '104.16.0.1');

printf("\n%d passed, %d failed\n",$pass,$fail);
exit($fail?1:0);
