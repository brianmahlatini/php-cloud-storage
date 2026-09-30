<?php

declare(strict_types=1);

namespace CloudStorage;

/**
 * Provider-neutral contract: the application asks for a time-limited URL and
 * the browser uploads/downloads directly to the cloud. File bytes never pass
 * through PHP (no memory/time limits, no bandwidth cost on the app server).
 */
interface ObjectStorage
{
    public function uploadUrl(string $key, string $contentType, int $ttlSeconds): PresignedUrl;

    public function downloadUrl(string $key, int $ttlSeconds, ?string $downloadFilename = null): PresignedUrl;
}
