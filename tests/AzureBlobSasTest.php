<?php

declare(strict_types=1);

namespace CloudStorage\Tests;

use CloudStorage\AzureBlobSas;
use PHPUnit\Framework\TestCase;

final class AzureBlobSasTest extends TestCase
{
    private const KEY = 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=='; // Azurite's public dev key

    private function sas(?string $endpoint = null): AzureBlobSas
    {
        return new AzureBlobSas('devstoreaccount1', self::KEY, 'uploads', $endpoint, static fn(): \DateTimeImmutable => new \DateTimeImmutable('2026-03-01T10:00:00Z'));
    }

    /** @return array<string, string> */
    private static function query(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);

        /** @var array<string, string> $q */
        return $q;
    }

    public function testSignatureMatchesDocumentedStringToSign(): void
    {
        $url = $this->sas()->sign('docs/report.pdf', 'r', 3600)[0];
        $q = self::query($url);
        $expected = implode("\n", ['r', '2026-03-01T09:55:00Z', '2026-03-01T11:00:00Z', '/blob/devstoreaccount1/uploads/docs/report.pdf', '', '', 'https', AzureBlobSas::VERSION, 'b', '', '', '', '', '', '', '']);
        self::assertSame(base64_encode(hash_hmac('sha256', $expected, (string) base64_decode(self::KEY, true), true)), $q['sig']);
        self::assertSame(['sv', 'spr', 'st', 'se', 'sr', 'sp', 'sig'], array_keys($q));
        self::assertStringStartsWith('https://devstoreaccount1.blob.core.windows.net/uploads/docs/report.pdf?', $url);
    }

    public function testUploadIsCreateWriteOnlyAndPinsContentType(): void
    {
        $p = $this->sas()->uploadUrl('img/cat.png', 'image/png', 600);
        $q = self::query($p->url);
        self::assertSame('cw', $q['sp']);
        self::assertSame('image/png', $q['rsct']);
        self::assertSame(['x-ms-blob-type' => 'BlockBlob', 'content-type' => 'image/png'], $p->requiredHeaders);
        self::assertSame('PUT', $p->method);
    }

    public function testStartTimeAllowsClockSkewAndExpiryIsExact(): void
    {
        $p = $this->sas()->downloadUrl('a.txt', 900);
        $q = self::query($p->url);
        self::assertSame('2026-03-01T09:55:00Z', $q['st']);
        self::assertSame('2026-03-01T10:15:00Z', $q['se']);
        self::assertSame('2026-03-01T10:15:00+00:00', $p->expiresAt->format('c'));
    }

    public function testAzuriteEndpointAllowsHttp(): void
    {
        $url = $this->sas('http://127.0.0.1:10000/devstoreaccount1')->downloadUrl('a.txt', 60)->url;
        self::assertStringStartsWith('http://127.0.0.1:10000/devstoreaccount1/uploads/a.txt?', $url);
        self::assertSame('https,http', self::query($url)['spr']);
    }

    public function testRejectsBadPermissionsAndLongTtl(): void
    {
        foreach (['', 'rr', 'rx', 'R'] as $perm) {
            try {
                $this->sas()->sign('k', $perm, 60);
                self::fail("accepted permissions {$perm}");
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        $this->expectException(\InvalidArgumentException::class);
        $this->sas()->sign('k', 'r', 8 * 24 * 3600);
    }

    public function testValidatesNames(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new AzureBlobSas('Bad-Account', self::KEY, 'uploads');
    }
}
