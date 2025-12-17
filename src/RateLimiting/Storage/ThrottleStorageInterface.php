<?php

namespace Codemonster\Security\RateLimiting\Storage;

interface ThrottleStorageInterface
{
    public function get(string $key): mixed;
    public function put(string $key, mixed $value): void;
    public function forget(string $key): void;
}

