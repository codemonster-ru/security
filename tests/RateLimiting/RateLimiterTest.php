<?php

namespace Codemonster\Security\Tests\RateLimiting;

use Codemonster\Security\RateLimiting\RateLimiter;
use Codemonster\Security\RateLimiting\Storage\SessionThrottleStorage;
use Codemonster\Session\Session;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    public function testTracksAttemptsAndExpiry(): void
    {
        Session::start('array');

        $now = 1000;
        $limiter = new RateLimiter(new SessionThrottleStorage(), function () use (&$now) {
            return $now;
        });

        $key = 'login:' . sha1('a');

        $this->assertFalse($limiter->tooManyAttempts($key, 2));
        $this->assertSame(1, $limiter->hit($key, 10));
        $this->assertSame(2, $limiter->hit($key, 10));
        $this->assertTrue($limiter->tooManyAttempts($key, 2));
        $this->assertSame(10, $limiter->availableIn($key));

        $now = 1011;

        $this->assertFalse($limiter->tooManyAttempts($key, 2));
        $this->assertSame(0, $limiter->availableIn($key));
    }
}
