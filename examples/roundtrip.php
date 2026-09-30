<?php

declare(strict_types=1);

/**
 * End-to-end check against real S3-compatible and Azure-compatible servers
 * (SeaweedFS and Azurite in CI): presign an upload, PUT bytes with plain HTTP as
 * a browser would, presign a download, GET them back, compare.
 *
 * Usage: php examples/roundtrip.php s3|azure
 */

use CloudStorage\AzureBlobSas;
use CloudStorage\Credentials;
use CloudStorage\ObjectStorage;
use CloudStorage\S3Presigner;

require dirname(__DIR__) . '/vendor/autoload.php';

/** @param array<string, string> $headers */
function http(string $method, string $url, array $headers = [], ?string $body = null): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => array_map(static fn(string $k, string $v): string => "{$k}: {$v}", array_keys($headers), $headers),
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_TIMEOUT => 15,
    ]);
    $out = (string) curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return [$status, $out];
}

$storage = match ($argv[1] ?? '') {
    's3' => new S3Presigner(new Credentials('s3test', 's3test-secret'), 'roundtrip-bucket', 'us-east-1', 'http://127.0.0.1:8333'),
    'azure' => new AzureBlobSas('devstoreaccount1', 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==', 'roundtrip', 'http://127.0.0.1:10000/devstoreaccount1'),
    default => (fwrite(STDERR, "usage: roundtrip.php s3|azure\n") && exit(2)),
};
assert($storage instanceof ObjectStorage);

$key = 'ci/' . bin2hex(random_bytes(4)) . '/hello world.txt';
$payload = 'hello from php-cloud-storage ' . date('c');

$up = $storage->uploadUrl($key, 'text/plain', 120);
[$status] = http('PUT', $up->url, $up->requiredHeaders, $payload);
if ($status < 200 || $status >= 300) {
    fwrite(STDERR, "upload failed: HTTP {$status}\n");
    exit(1);
}

[$status, $body] = http('GET', $storage->downloadUrl($key, 120)->url);
if ($status !== 200 || $body !== $payload) {
    fwrite(STDERR, "download failed: HTTP {$status}, body " . json_encode($body) . "\n");
    exit(1);
}

// A tampered URL must be refused by the server.
[$status] = http('GET', str_replace('hello%20world', 'hello%20World', $storage->downloadUrl($key, 120)->url));
if ($status < 400) {
    fwrite(STDERR, "tampered URL was accepted (HTTP {$status})\n");
    exit(1);
}

echo "OK {$argv[1]}: uploaded and downloaded {$key} via presigned URLs; tampered URL rejected\n";
