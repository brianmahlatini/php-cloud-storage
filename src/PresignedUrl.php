<?php

declare(strict_types=1);

namespace CloudStorage;

final class PresignedUrl
{
    public function __construct(
        public readonly string $url,
        public readonly string $method,
        public readonly \DateTimeImmutable $expiresAt,
        /** @var array<string, string> headers the client must send exactly */
        public readonly array $requiredHeaders = [],
    ) {}
}
