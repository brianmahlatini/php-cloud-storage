# php-cloud-storage

Dependency-free PHP 8.3 library that issues **presigned upload and download URLs for AWS S3 (Signature Version 4) and Azure Blob Storage (service SAS)** behind one interface. Browsers upload straight to the cloud, so file bytes never pass through your PHP servers.

The S3 signer reproduces AWS's **published reference signature byte for byte**. CI then proves both signers against real servers, **MinIO** (S3 API) and **Azurite** (Azure's official emulator): upload, download, and rejection of a tampered URL.

```php
$storage = new S3Presigner(new Credentials($keyId, $secret, $sessionToken), 'my-uploads', 'eu-west-1');
// or: new AzureBlobSas('mystorageacct', $accountKey, 'uploads');

$upload = $storage->uploadUrl("users/{$userId}/avatar.png", 'image/png', ttlSeconds: 300);
// return $upload->url and $upload->requiredHeaders to the browser, which does:
//   fetch(url, { method: 'PUT', headers: requiredHeaders, body: file })

$download = $storage->downloadUrl("users/{$userId}/avatar.png", 60, downloadFilename: 'avatar.png');
```

## Why presigned URLs

| Proxying uploads through PHP | Presigned direct upload |
|---|---|
| Every byte crosses your server twice (in and out) | Bytes go browser → cloud |
| `upload_max_filesize`, `memory_limit`, request timeouts | Limited only by the storage service |
| App servers need broad storage write credentials | The URL grants one operation, on one key, for minutes |

## Security decisions

- **Scope every URL tightly.** S3 upload URLs sign `Content-Type`, so a URL issued for `image/png` can't be used to upload `text/html`. Azure upload tokens are create+write only (`cw`): the holder can't read or list anything.
- **Short-lived by construction.** TTLs are validated (S3 ≤ 7 days per the SigV4 limit; Azure capped at 7 days because an account-key SAS can only be revoked by rotating the key). Azure start times are backdated 5 minutes to tolerate client clock skew.
- **Safe object keys.** `..`, leading `/`, backslashes and control characters are rejected before signing, so user input can't escape a prefix.
- **Safe download names.** `Content-Disposition` filenames are sanitised, which blocks header injection via `\r\n` and quotes.
- **Secrets stay out of logs.** Credentials use `#[\SensitiveParameter]` (redacted from stack traces) and `__debugInfo()` (redacted from `var_dump`/`print_r`).
- **Temporary credentials supported.** STS session tokens (IAM roles, IRSA, ECS task roles) are signed in, so no long-lived access keys are needed.
- **Encoding done by the spec.** RFC 3986 encoding with `/` preserved in paths, sorted canonical query, trimmed header values. Most hand-rolled SigV4 bugs come from these details, and the AWS known-answer test pins them.

## Testing

| Layer | What it proves |
|---|---|
| AWS reference vector | SigV4 canonical request, string to sign and signing-key derivation are exactly right |
| Unit tests (15) | Signed headers, session tokens, filename sanitising, path-style endpoints, Azure string-to-sign, permissions, TTL and name validation, secret redaction |
| Interop in CI | Real `PUT`/`GET` against MinIO and Azurite; a modified URL is rejected by the server |
| Static analysis | PHPStan level 9, PHP-CS-Fixer (PER-CS 2.0), PHP 8.3 and 8.4 |

The Azure account key in the tests is Azurite's publicly documented development key, not a real credential.

## License

MIT
