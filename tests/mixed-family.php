<?php
declare(strict_types=1);
require __DIR__ . '/../src/IP.php';
use ArrayPress\IPUtils\IP;
$pass=0;$fail=0;
function ok(string $l, bool $c): void { global $pass,$fail; if($c){printf("  PASS  %s\n",$l);$pass++;}else{printf("  FAIL  %s\n",$l);$fail++;} }

echo "Mixed-family lists (previously a fatal ArithmeticError)\n";
$mixed = ['10.0.0.0/8','2606:4700::/32','192.168.1.5','203.0.113.*'];
ok('v4 against mixed list does not crash',   IP::is_match('8.8.8.8', $mixed) === false);
ok('v6 against mixed list does not crash',   IP::is_match('2001:4860:4860::8888', $mixed) === false);
ok('v4 still matches its v4 range',          IP::is_match('10.1.2.3', $mixed) === true);
ok('v6 still matches its v6 range',          IP::is_match('2606:4700::1', $mixed) === true);
ok('exact v4 match still works',             IP::is_match('192.168.1.5', $mixed) === true);
ok('wildcard still works',                   IP::is_match('203.0.113.9', $mixed) === true);
ok('v4 vs v6 range is a miss, not a crash',  IP::is_in_range('8.8.8.8','::1/128') === false);
ok('v6 vs v4 range is a miss, not a crash',  IP::is_in_range('::1','10.0.0.0/8') === false);
printf("\n%d passed, %d failed\n",$pass,$fail);
exit($fail?1:0);
