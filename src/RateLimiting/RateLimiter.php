<?php

namespace Codemonster\Security\RateLimiting;

use Codemonster\Security\RateLimiting\Contracts\RateLimiterInterface;
use Codemonster\Security\RateLimiting\Storage\ThrottleStorageInterface;

class RateLimiter implements RateLimiterInterface
{
    protected ThrottleStorageInterface $storage;
    /** @var callable(): int */
    protected $now;

    public function __construct(ThrottleStorageInterface $storage, ?callable $now = null)
    {
        $this->storage = $storage;
        $this->now = $now ?? static fn() => time();
    }

    public function tooManyAttempts(string $key, int $maxAttempts): bool
    {
        $record = $this->record($key);

        if (!$record) {
            return false;
        }

        if ($this->isExpired($record)) {
            $this->clear($key);

            return false;
        }

        return (int) ($record['attempts'] ?? 0) >= $maxAttempts;
    }

    public function hit(string $key, int $decaySeconds): int
    {
        $record = $this->record($key);
        $now = ($this->now)();

        if (!$record || $this->isExpired($record)) {
            $record = [
                'attempts' => 0,
                'expires_at' => $now + $decaySeconds,
            ];
        }

        $record['attempts'] = (int) ($record['attempts'] ?? 0) + 1;

        $this->storage->put($key, $record);

        return $record['attempts'];
    }

    public function availableIn(string $key): int
    {
        $record = $this->record($key);

        if (!$record) {
            return 0;
        }

        $now = ($this->now)();
        $expiresAt = (int) ($record['expires_at'] ?? 0);

        return max(0, $expiresAt - $now);
    }

    public function clear(string $key): void
    {
        $this->storage->forget($key);
    }

    protected function record(string $key): ?array
    {
        $value = $this->storage->get($key);

        return is_array($value) ? $value : null;
    }

    protected function isExpired(array $record): bool
    {
        $expiresAt = (int) ($record['expires_at'] ?? 0);
        $now = ($this->now)();

        return $expiresAt !== 0 && $now >= $expiresAt;
    }
}
