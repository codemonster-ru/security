<?php

namespace Codemonster\Security\RateLimiting\Storage;

use Codemonster\Database\Contracts\ConnectionInterface;
use PDO;

class DatabaseThrottleStorage implements AtomicThrottleStorageInterface
{
    protected ConnectionInterface $connection;
    protected string $table;

    public function __construct(ConnectionInterface $connection, string $table = 'throttle_requests')
    {
        $this->connection = $connection;
        $this->table = $table;
    }

    public function get(string $key): mixed
    {
        return $this->connection->table($this->table)->where('key', $key)->first();
    }

    public function put(string $key, mixed $value): void
    {
        if (!is_array($value)) {
            return;
        }

        $record = [
            'attempts' => (int) ($value['attempts'] ?? 0),
            'expires_at' => (int) ($value['expires_at'] ?? 0),
        ];

        $existing = $this->connection->table($this->table)->where('key', $key)->first();

        if ($existing) {
            $this->connection->table($this->table)->where('key', $key)->update($record);

            return;
        }

        $this->connection->table($this->table)->insert(array_merge(['key' => $key], $record));
    }

    public function forget(string $key): void
    {
        $this->connection->table($this->table)->where('key', $key)->delete();
    }

    public function increment(string $key, int $decaySeconds, int $now): array
    {
        $expiresAt = $now + $decaySeconds;
        $driver = $this->connection->getPdo()->getAttribute(PDO::ATTR_DRIVER_NAME);

        if ($driver === 'mysql') {
            $sql = sprintf(
                'INSERT INTO `%s` (`key`, `attempts`, `expires_at`) VALUES (?, 1, ?)
                ON DUPLICATE KEY UPDATE
                    `attempts` = IF(`expires_at` <= ?, 1, `attempts` + 1),
                    `expires_at` = IF(`expires_at` <= ?, ?, `expires_at`)',
                $this->table
            );

            $this->connection->statement($sql, [$key, $expiresAt, $now, $now, $expiresAt]);

            $record = $this->connection->table($this->table)->where('key', $key)->first() ?? [];

            return [
                'attempts' => (int) ($record['attempts'] ?? 1),
                'expires_at' => (int) ($record['expires_at'] ?? $expiresAt),
            ];
        }

        $record = ['attempts' => 1, 'expires_at' => $expiresAt];

        $this->connection->transaction(function (ConnectionInterface $connection) use ($key, $decaySeconds, $now, &$record) {
            $row = $connection->table($this->table)->where('key', $key)->first();
            $expiresAt = $now + $decaySeconds;

            if (!$row || (int) ($row['expires_at'] ?? 0) <= $now) {
                $record = ['attempts' => 1, 'expires_at' => $expiresAt];

                if ($row) {
                    $connection->table($this->table)->where('key', $key)->update($record);
                } else {
                    $connection->table($this->table)->insert(array_merge(['key' => $key], $record));
                }

                return;
            }

            $attempts = (int) ($row['attempts'] ?? 0) + 1;
            $record = ['attempts' => $attempts, 'expires_at' => (int) ($row['expires_at'] ?? $expiresAt)];

            $connection->table($this->table)->where('key', $key)->update(['attempts' => $attempts]);
        });

        return $record;
    }
}
