<?php

declare(strict_types=1);

namespace CloudStorage;

final class Keys
{
    /**
     * Rejects keys that could escape a prefix or confuse path normalisation
     * (../, leading slash, control characters, backslashes).
     */
    public static function assertSafe(string $key): void
    {
        if ($key === '' || strlen($key) > 1024) {
            throw new \InvalidArgumentException('Object key must be 1-1024 bytes.');
        }
        if (str_starts_with($key, '/') || str_contains($key, '\\') || preg_match('#(^|/)\.\.?(/|$)#', $key) === 1 || preg_match('/[\x00-\x1f\x7f]/', $key) === 1) {
            throw new \InvalidArgumentException("Unsafe object key: {$key}");
        }
    }

    public static function assertTtl(int $ttl, int $max): void
    {
        if ($ttl < 1 || $ttl > $max) {
            throw new \InvalidArgumentException("TTL must be between 1 and {$max} seconds.");
        }
    }

    /** RFC 3986 encoding; AWS and Azure both require '~' left unencoded and spaces as %20. */
    public static function encode(string $s, bool $keepSlash = false): string
    {
        $e = rawurlencode($s);

        return $keepSlash ? str_replace('%2F', '/', $e) : $e;
    }
}
