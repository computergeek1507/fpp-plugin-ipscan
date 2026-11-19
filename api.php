<?php
// REST endpoints, served by FPP at /api/plugin/fpp-plugin-ipscan/<endpoint>
//
//   GET  defaults     suggested range for each of this box's networks
//   POST scan         start a scan  {"start":"..","end":".."} or {"cidr":".."}
//                     optional: "ports":"22,80", "timeout":1, "dns":true
//   GET  status       progress and the hosts found so far
//   POST stop         stop a running scan
//   GET  results.csv  last scan as CSV (also .json)
//
// Every function here is prefixed ipscan so it can't clash with FPP's own.

function getEndpointsfpppluginipscan() {
    return array(
        array('method' => 'GET',  'endpoint' => 'defaults',     'callback' => 'ipscanApiDefaults'),
        array('method' => 'POST', 'endpoint' => 'scan',         'callback' => 'ipscanApiScan'),
        array('method' => 'GET',  'endpoint' => 'status',       'callback' => 'ipscanApiStatus'),
        array('method' => 'POST', 'endpoint' => 'stop',         'callback' => 'ipscanApiStop'),
        array('method' => 'GET',  'endpoint' => 'results.csv',  'callback' => 'ipscanApiResultsCsv'),
        array('method' => 'GET',  'endpoint' => 'results.json', 'callback' => 'ipscanApiResultsJson'),
    );
}

define('IPSCAN_MAX_HOSTS', 4096);

function ipscanDataDir() {
    global $settings;
    $media = isset($settings['mediaDirectory']) ? $settings['mediaDirectory'] : '/home/fpp/media';
    $dir = $media . '/plugindata/fpp-plugin-ipscan';
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    return $dir;
}

function ipscanReadStatus() {
    $file = ipscanDataDir() . '/status.json';
    if (!is_file($file)) {
        return array('state' => 'idle', 'total' => 0, 'done' => 0, 'alive' => 0, 'hosts' => array());
    }
    $st = json_decode(file_get_contents($file), true);
    if (!is_array($st)) {
        return array('state' => 'idle', 'total' => 0, 'done' => 0, 'alive' => 0, 'hosts' => array());
    }
    // A scan whose process is gone (reboot, kill -9) is not still running.
    if ($st['state'] == 'running' && (empty($st['pid']) || !file_exists('/proc/' . intval($st['pid'])))) {
        $st['state'] = 'stopped';
    }
    return $st;
}

function ipscanError($msg) {
    http_response_code(400);
    return json(array('status' => 'ERROR', 'message' => $msg));
}

// Each IPv4 network on this box (skipping loopback and link-local), as a
// suggested scan range. Uses /24 at most so a /16 doesn't suggest 65k hosts.
function ipscanApiDefaults() {
    $nets = array();
    if (function_exists('net_get_interfaces')) {
        foreach (net_get_interfaces() as $name => $iface) {
            if (empty($iface['unicast'])) continue;
            foreach ($iface['unicast'] as $u) {
                if (!isset($u['family']) || $u['family'] != AF_INET || empty($u['address']) || empty($u['netmask'])) continue;
                $ip = ip2long($u['address']);
                $mask = ip2long($u['netmask']);
                if ($ip === false || $mask === false) continue;
                if (($ip >> 24) == 127 || ($ip & 0xFFFF0000) == ip2long('169.254.0.0')) continue;
                $bits = 32 - (int)log((~$mask & 0xFFFFFFFF) + 1, 2);
                if ($bits < 24) {
                    $mask = ip2long('255.255.255.0');
                }
                $net = $ip & $mask;
                $bcast = $net | (~$mask & 0xFFFFFFFF);
                $nets[] = array(
                    'interface' => $name,
                    'address' => $u['address'],
                    'start' => long2ip($net + 1),
                    'end' => long2ip($bcast - 1),
                );
            }
        }
    }
    return json(array('networks' => $nets));
}

function ipscanApiScan() {
    $in = json_decode(file_get_contents('php://input'), true);
    if (!is_array($in)) $in = $_POST;

    $st = ipscanReadStatus();
    if ($st['state'] == 'running') {
        return ipscanError('A scan is already running');
    }

    $args = array();
    if (!empty($in['cidr'])) {
        if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', trim($in['cidr']), $m)
            || ip2long($m[1]) === false || $m[2] > 32) {
            return ipscanError('Invalid CIDR');
        }
        if ((1 << (32 - $m[2])) > IPSCAN_MAX_HOSTS + 2) {
            return ipscanError('Range too large (max ' . IPSCAN_MAX_HOSTS . ' hosts)');
        }
        $args = array('-f:cidr', trim($in['cidr']));
    } else {
        $start = isset($in['start']) ? trim($in['start']) : '';
        $end = isset($in['end']) ? trim($in['end']) : '';
        $a = ip2long($start);
        $b = ip2long($end);
        if ($a === false || $b === false || !filter_var($start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            || !filter_var($end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ipscanError('Start and end must be IPv4 addresses');
        }
        if (abs(sprintf('%u', $b) - sprintf('%u', $a)) + 1 > IPSCAN_MAX_HOSTS) {
            return ipscanError('Range too large (max ' . IPSCAN_MAX_HOSTS . ' hosts)');
        }
        $args = array('-f:range', $start, $end);
    }

    if (!empty($in['ports'])) {
        if (!preg_match('/^\d{1,5}(,\s*\d{1,5})*$/', $in['ports'])) {
            return ipscanError('Ports must be numbers separated by commas');
        }
        $args[] = '--ports';
        $args[] = preg_replace('/\s+/', '', $in['ports']);
    }
    if (isset($in['timeout']) && is_numeric($in['timeout'])) {
        $args[] = '--timeout';
        $args[] = (string)max(0.2, min(5.0, floatval($in['timeout'])));
    }
    if (isset($in['dns']) && !$in['dns']) {
        $args[] = '--no-dns';
    }

    $dir = ipscanDataDir();
    $args = array_merge($args, array(
        '-s', '-q',
        '-o', $dir . '/results.csv',
        '--status', $dir . '/status.json',
        '--max-hosts', (string)IPSCAN_MAX_HOSTS,
    ));
    $cmd = 'python3 ' . escapeshellarg(__DIR__ . '/scripts/ipscan.py');
    foreach ($args as $arg) {
        $cmd .= ' ' . escapeshellarg($arg);
    }
    // Detach so the scan outlives this request.
    exec('nohup ' . $cmd . ' > ' . escapeshellarg($dir . '/scan.log') . ' 2>&1 & echo $!', $out);
    $pid = isset($out[0]) ? intval($out[0]) : 0;

    // Give the scanner a moment to write its first status file so the page
    // sees "running" straight away.
    for ($i = 0; $i < 20; $i++) {
        usleep(100000);
        $st = ipscanReadStatus();
        if (isset($st['pid']) && $st['pid'] == $pid) break;
    }
    // Fine if the scanner wrote a status file (a tiny range can finish
    // before we look); a failure only if it never did and is already gone.
    if ((!isset($st['pid']) || $st['pid'] != $pid) && !file_exists("/proc/$pid")) {
        $log = @file_get_contents($dir . '/scan.log');
        return ipscanError('Scanner failed to start: ' . trim($log));
    }
    return json(array('status' => 'OK', 'pid' => $pid));
}

function ipscanApiStatus() {
    return json(ipscanReadStatus());
}

function ipscanApiStop() {
    $st = ipscanReadStatus();
    if ($st['state'] == 'running' && !empty($st['pid'])) {
        $pid = intval($st['pid']);
        // Only signal it if it really is our scanner.
        $cmdline = @file_get_contents("/proc/$pid/cmdline");
        if ($cmdline !== false && strpos($cmdline, 'ipscan.py') !== false) {
            if (function_exists('posix_kill')) {
                posix_kill($pid, 15);
            } else {
                exec('kill ' . $pid);
            }
        }
    }
    return json(array('status' => 'OK'));
}

function ipscanApiResultsCsv() {
    $file = ipscanDataDir() . '/results.csv';
    if (!is_file($file)) {
        http_response_code(404);
        return json(array('status' => 'ERROR', 'message' => 'No results yet'));
    }
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="ipscan-' . date('Ymd-His', filemtime($file)) . '.csv"');
    readfile($file);
    exit(0);
}

function ipscanApiResultsJson() {
    $st = ipscanReadStatus();
    return json($st['hosts']);
}
?>
