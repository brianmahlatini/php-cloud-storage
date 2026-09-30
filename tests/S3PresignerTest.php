<?php

declare(strict_types=1);

namespace CloudStorage\Tests;

use CloudStorage\Credentials;
use CloudStorage\S3Presigner;
use PHPUnit\Framework\TestCase;

final class S3PresignerTest extends TestCase
{
    private static function clockAt(string $iso): \Closure
    {
        return static fn(): \DateTimeImmutable => new \DateTimeImmutable($iso);
    }

    /** Known-answer test from the AWS SigV4 query-string documentation. */
    public function testMatchesAwsPublishedExample(): void
    {
        $s3 = new S3Presigner(
            new Credentials('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
            'examplebucket',
            'us-east-1',
            clock: self::clockAt('2013-05-24T00:00:00Z'),
        );
        $url = $s3->presign('GET', 'test.txt', 86400)->url;
        self::assertSame(
            'https://examplebucket.s3.amazonaws.com/test.txt'
            . '?X-Amz-Algorithm=AWS4-HMAC-SHA256'
            . '&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request'
            . '&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host'
            . '&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404',
            $url,
        );
    }

    public function testUploadSignsContentTypeAndReportsRequiredHeaders(): void
    {
        $s3 = new S3Presigner(new Credentials('AKIDEXAMPLE', 'secret'), 'uploads-bucket', 'eu-west-1', clock: self::clockAt('2026-01-01T12:00:00Z'));
        $p = $s3->uploadUrl('users/42/avatar image.png', 'image/png', 300);
        self::assertSame('PUT', $p->method);
        self::assertStringStartsWith('https://uploads-bucket.s3.eu-west-1.amazonaws.com/users/42/avatar%20image.png?', $p->url);
        self::assertStringContainsString('X-Amz-SignedHeaders=content-type%3Bhost', $p->url);
        self::assertSame(['content-type' => 'image/png'], $p->requiredHeaders);
        self::assertSame('2026-01-01T12:05:00+00:00', $p->expiresAt->format('c'));
    }

    public function testDifferentContentTypeGivesDifferentSignature(): void
    {
        $s3 = new S3Presigner(new Credentials('AKIDEXAMPLE', 'secret'), 'uploads-bucket', 'eu-west-1', clock: self::clockAt('2026-01-01T12:00:00Z'));
        self::assertNotSame($s3->uploadUrl('a.png', 'image/png', 60)->url, $s3->uploadUrl('a.png', 'text/html', 60)->url);
    }

    public function testSessionTokenIsIncludedForTemporaryCredentials(): void
    {
        $s3 = new S3Presigner(new Credentials('ASIAEXAMPLE', 'secret', 'token/with+chars='), 'b-bucket', 'eu-west-1', clock: self::clockAt('2026-01-01T00:00:00Z'));
        self::assertStringContainsString('X-Amz-Security-Token=token%2Fwith%2Bchars%3D', $s3->downloadUrl('k', 60)->url);
    }

    public function testDownloadFilenameIsSanitised(): void
    {
        $s3 = new S3Presigner(new Credentials('AKID', 'secret'), 'b-bucket', 'eu-west-1', clock: self::clockAt('2026-01-01T00:00:00Z'));
        $url = $s3->downloadUrl('reports/q1.pdf', 60, "Q1 \"report\"\r\n.pdf")->url;
        self::assertStringContainsString('response-content-disposition=attachment%3B%20filename%3D%22Q1%20_report___.pdf%22', $url);
    }

    public function testPathStyleForCustomEndpoints(): void
    {
        $s3 = new S3Presigner(new Credentials('minio', 'minio-secret'), 'local-bucket', 'us-east-1', 'http://localhost:9000', self::clockAt('2026-01-01T00:00:00Z'));
        self::assertStringStartsWith('http://localhost:9000/local-bucket/file.txt?', $s3->downloadUrl('file.txt', 60)->url);
    }

    /** @return iterable<array{string}> */
    public static function unsafeKeys(): iterable
    {
        return [['../etc/passwd'], ['/absolute'], ['a/../b'], ["new\nline"], ['back\\slash'], ['']];
    }

    public function testRejectsUnsafeKeys(): void
    {
        $s3 = new S3Presigner(new Credentials('AKID', 'secret'), 'b-bucket', 'eu-west-1');
        foreach (self::unsafeKeys() as [$key]) {
            try {
                $s3->downloadUrl($key, 60);
                self::fail('accepted unsafe key ' . json_encode($key));
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testRejectsTtlBeyondSevenDaysAndBadBuckets(): void
    {
        $s3 = new S3Presigner(new Credentials('AKID', 'secret'), 'b-bucket', 'eu-west-1');
        try {
            $s3->downloadUrl('k', 604801);
            self::fail('accepted TTL > 7 days');
        } catch (\InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
        $this->expectException(\InvalidArgumentException::class);
        new S3Presigner(new Credentials('AKID', 'secret'), 'Bad_Bucket', 'eu-west-1');
    }

    public function testSecretsAreHiddenFromDumps(): void
    {
        $dump = print_r(new Credentials('AKID', 'super-secret-value', 'tok'), true);
        self::assertStringNotContainsString('super-secret-value', $dump);
        self::assertStringNotContainsString('tok)', $dump);
    }
}
