<?php

namespace Codemonster\Security\RateLimiting\Storage;

use Codemonster\Session\Session;
use Codemonster\Session\Store;

class SessionThrottleStorage implements ThrottleStorageInterface
{
    protected Store $session;
    protected string $prefix;

    public function __construct(?Store $session = null, string $prefix = 'throttle:')
    {
        $this->session = $session ?? Session::store();
        $this->prefix = $prefix;
    }

    public function get(string $key): mixed
    {
        return $this->session->get($this->prefix . $key);
    }

    public function put(string $key, mixed $value): void
    {
        $this->session->put($this->prefix . $key, $value);
    }

    public function forget(string $key): void
    {
        $this->session->forget($this->prefix . $key);
    }
}
