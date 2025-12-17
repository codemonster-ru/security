# Changelog

All notable changes to this package will be documented in this file.

## [1.0.0] - 2025-12-17

### Added

- CSRF: `Codemonster\Security\Csrf\VerifyCsrfToken`, token manager `Codemonster\Security\Csrf\CsrfTokenManager`, helpers `csrf_token()` and `csrf_field()`.
- Rate limiting: `Codemonster\Security\RateLimiting\ThrottleRequests`, `Codemonster\Security\RateLimiting\RateLimiter`, storage contracts and `SessionThrottleStorage`.
- Integration with Annabel: `Codemonster\Security\Providers\SecurityServiceProvider`.
- Tests for CSRF and rate limiter.
