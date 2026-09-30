<?php

declare(strict_types=1);

namespace CloudStorage;

/**
 * Azure Blob Storage service SAS (blob-scoped, account-key signed), built
 * from the documented string-to-sign for service version 2020-12-06+.
 *
 * https://learn.microsoft.com/rest/api/storageservices/create-service-sas
 *
 * In production prefer a *user delegation* SAS (signed with an Entra ID
 * key rather than the account key); the string-to-sign differs only in the
 * delegation fields, and this class isolates that choice.
 */
final class AzureBlobSas implements ObjectStorage
{
    public const VERSION = '2022-11-02';
    private const MAX_TTL = 7 * 24 * 3600; // keep SAS short-lived; revocation requires rotating the key

    /** @var \Closure(): \DateTimeImmutable */
    private readonly \Closure $clock;

    /** @param (callable(): \DateTimeImmutable)|null $clock */
    public function __construct(
        private readonly string $account,
        #[\SensitiveParameter]
        private readonly string $accountKeyBase64,
        private readonly string $container,
        private readonly ?string $endpoint = null, // e.g. Azurite: http://127.0.0.1:10000/devstoreaccount1
        ?callable $clock = null,
    ) {
        if (preg_match('/^[a-z0-9]{3,24}$/', $account) !== 1) {
            throw new \InvalidArgumentException('Invalid storage account name.');
        }
        if (preg_match('/^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$/', $container) !== 1) {
            throw new \InvalidArgumentException('Invalid container name.');
        }
        if (base64_decode($accountKeyBase64, true) === false) {
            throw new \InvalidArgumentException('Account key must be base64.');
        }
        $this->clock = $clock !== null ? \Closure::fromCallable($clock) : static fn(): \DateTimeImmutable => new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function uploadUrl(string $key, string $contentType, int $ttlSeconds): PresignedUrl
    {
        // "cw": create + write only. The holder can't read or list anything.
        $url = $this->sign($key, 'cw', $ttlSeconds, ['rsct' => $contentType]);

        return new PresignedUrl($url[0], 'PUT', $url[1], ['x-ms-blob-type' => 'BlockBlob', 'content-type' => $contentType]);
    }

    public function downloadUrl(string $key, int $ttlSeconds, ?string $downloadFilename = null): PresignedUrl
    {
        $overrides = [];
        if ($downloadFilename !== null) {
            $overrides['rscd'] = 'attachment; filename="' . (preg_replace('/[^\w.\- ]/u', '_', $downloadFilename) ?? 'download') . '"';
        }
        $url = $this->sign($key, 'r', $ttlSeconds, $overrides);

        return new PresignedUrl($url[0], 'GET', $url[1]);
    }

    /**
     * @param array<string, string> $overrides response header overrides (rscc, rscd, rsce, rscl, rsct)
     * @return array{0: string, 1: \DateTimeImmutable}
     */
    public function sign(string $key, string $permissions, int $ttlSeconds, array $overrides = []): array
    {
        Keys::assertSafe($key);
        Keys::assertTtl($ttlSeconds, self::MAX_TTL);
        if (preg_match('/^(?!.*(.).*\1)[racwdt]+$/', $permissions) !== 1) {
            throw new \InvalidArgumentException('Permissions must be distinct letters from r,a,c,w,d,t.');
        }
        $now = ($this->clock)()->setTimezone(new \DateTimeZone('UTC'));
        $start = $now->modify('-5 minutes')->format('Y-m-d\TH:i:s\Z'); // tolerate client clock skew
        $expiry = $now->modify("+{$ttlSeconds} seconds");
        $expiryStr = $expiry->format('Y-m-d\TH:i:s\Z');
        $protocol = $this->endpoint !== null && str_starts_with($this->endpoint, 'http://') ? 'https,http' : 'https';

        $stringToSign = implode("\n", [
            $permissions,                                            // sp
            $start,                                                  // st
            $expiryStr,                                              // se
            "/blob/{$this->account}/{$this->container}/{$key}",      // canonicalized resource
            '',                                                      // si (stored access policy)
            '',                                                      // sip (IP range)
            $protocol,                                               // spr
            self::VERSION,                                           // sv
            'b',                                                     // sr: blob
            '',                                                      // snapshot time
            '',                                                      // encryption scope
            $overrides['rscc'] ?? '',
            $overrides['rscd'] ?? '',
            $overrides['rsce'] ?? '',
            $overrides['rscl'] ?? '',
            $overrides['rsct'] ?? '',
        ]);
        $sig = base64_encode(hash_hmac('sha256', $stringToSign, (string) base64_decode($this->accountKeyBase64, true), true));

        $query = ['sv' => self::VERSION, 'spr' => $protocol, 'st' => $start, 'se' => $expiryStr, 'sr' => 'b', 'sp' => $permissions] + $overrides + ['sig' => $sig];
        $base = $this->endpoint ?? "https://{$this->account}.blob.core.windows.net";
        $url = rtrim($base, '/') . '/' . $this->container . '/' . Keys::encode($key, true) . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return [$url, $expiry];
    }
}
