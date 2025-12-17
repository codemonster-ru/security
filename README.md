# codemonster-ru/security

[![Latest Version on Packagist](https://img.shields.io/packagist/v/codemonster-ru/security.svg?style=flat-square)](https://packagist.org/packages/codemonster-ru/security)
[![Total Downloads](https://img.shields.io/packagist/dt/codemonster-ru/security.svg?style=flat-square)](https://packagist.org/packages/codemonster-ru/security)
[![License](https://img.shields.io/packagist/l/codemonster-ru/security.svg?style=flat-square)](https://packagist.org/packages/codemonster-ru/security)
[![Tests](https://github.com/codemonster-ru/security/actions/workflows/tests.yml/badge.svg)](https://github.com/codemonster-ru/security/actions/workflows/tests.yml)

`codemonster-ru/security` is a set of reusable security components for the Annabel ecosystem:

- CSRF protection (`VerifyCsrfToken`) with a token from POST (`_token`) and/or headers (`X-CSRF-TOKEN`, `X-XSRF-TOKEN`)
- Rate limiting / brute-force protection (`ThrottleRequests`) with a configurable key and storage layer

No Laravel/Symfony dependencies. Compatible with `codemonster-ru/http` and `codemonster-ru/session`.

## Installation

```bash
composer require codemonster-ru/security
```

For monorepo development, you can use a `path` repository (as in `annabel-skeleton/composer.local.json`).

## Quick Start (Annabel)

Annabel loads providers from `bootstrap/providers/*.php`.

1. Add a provider:

`bootstrap/providers/SecurityServiceProvider.php`

```php
<?php

namespace App\Providers;

use Codemonster\Security\Providers\SecurityServiceProvider as BaseSecurityServiceProvider;

class SecurityServiceProvider extends BaseSecurityServiceProvider {}
```

2. Add config:

`config/security.php`

```php
<?php

return [
    'csrf' => [
        'enabled' => true,
        'add_to_kernel' => true,
        'verify_json' => false,
        'input_key' => '_token',
        'except_methods' => ['GET', 'HEAD', 'OPTIONS'],
        'except' => ['api/*'],
    ],
    'throttle' => [
        'enabled' => true,
        'add_to_kernel' => false,
        'max_attempts' => 60,
        'decay_seconds' => 60,
        'except' => [],
    ],
];
```

By default, CSRF is enabled globally (via `Kernel::addMiddleware`), but throttling is not (so as not to “surprise” all routes).

## CSRF

### How is it checked?

`Codemonster\Security\Csrf\VerifyCsrfToken`:

- Skips methods from `except_methods` (`GET/HEAD/OPTIONS` by default)
- By default, **does not validate JSON requests** (if `Accept: application/json`) to avoid breaking the API
- Validates the token:
- In the body: `_token` (configured via `input_key`)
- Or in the headers: `X-CSRF-TOKEN`, `X-XSRF-TOKEN`
- On error, returns `419` (`application/json` or `text/plain`)

### Helpers

The package autoloads helpers:

- `csrf_token(): string`
- `csrf_field(): string` — ready-to-use `<input type="hidden" name="_token" ...>`

Example in the form:

```php
echo '<form method="POST" action="/submit">';
echo csrf_field();
echo '<button type="submit">OK</button>';
echo '</form>';
```

## Throttle / Rate limiting

`Codemonster\Security\RateLimiting\ThrottleRequests`:

- stores the attempt counter in storage via `ThrottleStorageInterface`
- the package contains at least one implementation: `SessionThrottleStorage` (without a database)
- returns `429` + headers:
- `Retry-After` (seconds)
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`

### Connection to the route

Router/Kernel in Annabel supports route-level middleware:

```php
use Codemonster\Security\RateLimiting\ThrottleRequests;

$app->post('/login', fn($req) => 'ok')
    ->middleware(ThrottleRequests::class, '5,60'); // 5 attempts in 60 seconds
```

### Restriction key

By default, the key is built from `ip|method|uri` (and appends `email` from body if present) and hashed (`sha1`).

You can pass a callable instead of a role string:

```php
use Codemonster\Security\RateLimiting\ThrottleRequests;

$app->post('/login', fn($req) => 'ok')
    ->middleware(ThrottleRequests::class, function ($req) {
        return 'login:' . ($req->input('email') ?? 'guest') . '|' . ($req->header('X-Forwarded-For') ?? '0.0.0.0');
    });
```

## Tests

```bash
composer test
```

## License

[MIT](https://github.com/codemonster-ru/security/blob/main/LICENSE)
