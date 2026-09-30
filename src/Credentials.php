<?php

declare(strict_types=1);

namespace CloudStorage;

/** Secrets are kept out of var_dump/print_r output so they don't end up in logs. */
final class Credentials
{
    public function __construct(
        public readonly string $keyId,
        #[\SensitiveParameter]
        private readonly string $secret,
        public readonly ?string $sessionToken = null,
    ) {
        if ($keyId === '' || $secret === '') {
            throw new \InvalidArgumentException('Credentials must not be empty.');
        }
    }

    public function secret(): string
    {
        return $this->secret;
    }

    /** @return array<string, string|null> */
    public function __debugInfo(): array
    {
        return ['keyId' => $this->keyId, 'secret' => '***', 'sessionToken' => $this->sessionToken === null ? null : '***'];
    }
}
