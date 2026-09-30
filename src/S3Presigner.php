<?php

declare(strict_types=1);

namespace CloudStorage;

/**
 * AWS Signature Version 4 query-string presigning for S3, implemented from
 * the specification (no SDK). Verified against the published AWS example.
 *
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
 */
final class S3Presigner implements ObjectStorage
{
    private const MAX_TTL = 604800; // SigV4 hard limit: 7 days

    /** @var \Closure(): \DateTimeImmutable */
    private readonly \Closure $clock;

    /** @param (callable(): \DateTimeImmutable)|null $clock */
    public function __construct(
        private readonly Credentials $credentials,
        private readonly string $bucket,
        private readonly string $region,
        private readonly ?string $endpoint = null, // e.g. MinIO / LocalStack; path-style when set
        ?callable $clock = null,
    ) {
        if (preg_match('/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/', $bucket) !== 1) {
            throw new \InvalidArgumentException("Invalid S3 bucket name: {$bucket}");
        }
        $this->clock = $clock !== null ? \Closure::fromCallable($clock) : static fn(): \DateTimeImmutable => new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function uploadUrl(string $key, string $contentType, int $ttlSeconds): PresignedUrl
    {
        // Content-Type is signed, so the client can't upload an HTML file
        // disguised as an image to the key you intended for an image.
        return $this->presign('PUT', $key, $ttlSeconds, ['content-type' => $contentType]);
    }

    public function downloadUrl(string $key, int $ttlSeconds, ?string $downloadFilename = null): PresignedUrl
    {
        $extra = [];
        if ($downloadFilename !== null) {
            $safe = preg_replace('/[^\w.\- ]/u', '_', $downloadFilename) ?? 'download';
            $extra['response-content-disposition'] = 'attachment; filename="' . $safe . '"';
        }

        return $this->presign('GET', $key, $ttlSeconds, [], $extra);
    }

    /**
     * @param array<string, string> $signedHeaders extra headers (besides host) the client must send
     * @param array<string, string> $extraQuery
     */
    public function presign(string $method, string $key, int $ttlSeconds, array $signedHeaders = [], array $extraQuery = []): PresignedUrl
    {
        Keys::assertSafe($key);
        Keys::assertTtl($ttlSeconds, self::MAX_TTL);
        $now = ($this->clock)()->setTimezone(new \DateTimeZone('UTC'));
        $amzDate = $now->format('Ymd\THis\Z');
        $day = $now->format('Ymd');
        $scope = "{$day}/{$this->region}/s3/aws4_request";

        if ($this->endpoint !== null) {
            $parts = parse_url($this->endpoint);
            $host = ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');
            $scheme = $parts['scheme'] ?? 'https';
            $path = '/' . $this->bucket . '/' . Keys::encode($key, true);
        } else {
            // us-east-1 also answers on the legacy global hostname, which the
            // AWS reference example uses; other regions need the regional host.
            $host = $this->region === 'us-east-1' ? "{$this->bucket}.s3.amazonaws.com" : "{$this->bucket}.s3.{$this->region}.amazonaws.com";
            $scheme = 'https';
            $path = '/' . Keys::encode($key, true);
        }

        $headers = ['host' => $host] + array_change_key_case($signedHeaders, CASE_LOWER);
        ksort($headers);
        $signedHeaderNames = implode(';', array_keys($headers));

        $query = [
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => "{$this->credentials->keyId}/{$scope}",
            'X-Amz-Date' => $amzDate,
            'X-Amz-Expires' => (string) $ttlSeconds,
            'X-Amz-SignedHeaders' => $signedHeaderNames,
        ] + $extraQuery;
        if ($this->credentials->sessionToken !== null) {
            $query['X-Amz-Security-Token'] = $this->credentials->sessionToken;
        }
        $canonicalQuery = self::canonicalQuery($query);

        $canonicalHeaders = '';
        foreach ($headers as $name => $value) {
            $canonicalHeaders .= $name . ':' . trim((string) preg_replace('/\s+/', ' ', $value)) . "\n";
        }
        $canonicalRequest = implode("\n", [$method, $path, $canonicalQuery, $canonicalHeaders, $signedHeaderNames, 'UNSIGNED-PAYLOAD']);
        $stringToSign = implode("\n", ['AWS4-HMAC-SHA256', $amzDate, $scope, hash('sha256', $canonicalRequest)]);
        $signature = hash_hmac('sha256', $stringToSign, $this->signingKey($day));

        unset($headers['host']);

        return new PresignedUrl(
            "{$scheme}://{$host}{$path}?{$canonicalQuery}&X-Amz-Signature={$signature}",
            $method,
            $now->modify("+{$ttlSeconds} seconds"),
            $headers,
        );
    }

    private function signingKey(string $day): string
    {
        $k = hash_hmac('sha256', $day, 'AWS4' . $this->credentials->secret(), true);
        $k = hash_hmac('sha256', $this->region, $k, true);
        $k = hash_hmac('sha256', 's3', $k, true);

        return hash_hmac('sha256', 'aws4_request', $k, true);
    }

    /** @param array<string, string> $query */
    private static function canonicalQuery(array $query): string
    {
        $pairs = [];
        foreach ($query as $k => $v) {
            $pairs[Keys::encode($k)] = Keys::encode($v);
        }
        ksort($pairs, SORT_STRING);

        return implode('&', array_map(static fn(string $k, string $v): string => "{$k}={$v}", array_keys($pairs), $pairs));
    }
}
