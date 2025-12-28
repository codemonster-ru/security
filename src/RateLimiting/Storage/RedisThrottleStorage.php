<?php

namespace Codemonster\Security\RateLimiting\Storage;

class RedisThrottleStorage implements AtomicThrottleStorageInterface
{
    /** @var object */
    protected $client;
    protected string $prefix;

    public function __construct(object $client, string $prefix = 'throttle:')
    {
        $this->client = $client;
        $this->prefix = $prefix;
    }

    public function get(string $key): mixed
    {
        $redisKey = $this->prefix . $key;
        $value = $this->client->get($redisKey);

        if (!is_string($value)) {
            return null;
        }

        $ttl = $this->client->ttl($redisKey);
        $expiresAt = $ttl > 0 ? time() + $ttl : 0;

        return [
            'attempts' => (int) $value,
            'expires_at' => $expiresAt,
        ];
    }

    public function put(string $key, mixed $value): void
    {
        if (!is_array($value)) {
            return;
        }

        $attempts = (int) ($value['attempts'] ?? 0);
        $expiresAt = (int) ($value['expires_at'] ?? 0);
        $redisKey = $this->prefix . $key;

        if ($expiresAt > 0) {
            $ttl = max(0, $expiresAt - time());
            $this->client->setex($redisKey, $ttl, (string) $attempts);

            return;
        }

        $this->client->set($redisKey, (string) $attempts);
    }

    public function forget(string $key): void
    {
        $this->client->del($this->prefix . $key);
    }

    public function increment(string $key, int $decaySeconds, int $now): array
    {
        $redisKey = $this->prefix . $key;
        $script = <<<'LUA'
local key = KEYS[1]
local decay = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local ttl = redis.call('ttl', key)

if ttl == -2 then
    redis.call('set', key, 1, 'ex', decay)
    return {1, now + decay}
end

if ttl == -1 then
    redis.call('expire', key, decay)
    ttl = decay
end

local attempts = redis.call('incr', key)
return {attempts, now + ttl}
LUA;

        $result = $this->evalScript($script, [$redisKey], [$decaySeconds, $now]);

        if (!is_array($result) || count($result) < 2) {
            return ['attempts' => 1, 'expires_at' => $now + $decaySeconds];
        }

        return [
            'attempts' => (int) $result[0],
            'expires_at' => (int) $result[1],
        ];
    }

    protected function evalScript(string $script, array $keys, array $args): mixed
    {
        if (is_a($this->client, 'Redis')) {
            return $this->client->eval($script, array_merge($keys, $args), count($keys));
        }

        if (is_a($this->client, 'Predis\\Client')) {
            return $this->client->eval($script, count($keys), ...array_merge($keys, $args));
        }

        if (method_exists($this->client, 'eval')) {
            return $this->client->eval($script, count($keys), ...array_merge($keys, $args));
        }

        return null;
    }
}
