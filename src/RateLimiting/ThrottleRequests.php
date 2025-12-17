<?php

namespace Codemonster\Security\RateLimiting;

use Codemonster\Http\Request;
use Codemonster\Http\Response;
use Codemonster\Security\RateLimiting\Contracts\RateLimiterInterface;
use Codemonster\Security\RateLimiting\Storage\SessionThrottleStorage;

class ThrottleRequests
{
    protected RateLimiterInterface $limiter;
    protected int $maxAttempts;
    protected int $decaySeconds;
    protected array $exceptPaths;

    public function __construct(
        ?RateLimiterInterface $limiter = null,
        int $maxAttempts = 60,
        int $decaySeconds = 60,
        array $exceptPaths = []
    ) {
        $this->limiter = $limiter ?? new RateLimiter(new SessionThrottleStorage());
        $this->maxAttempts = $maxAttempts;
        $this->decaySeconds = $decaySeconds;
        $this->exceptPaths = $exceptPaths;
    }

    public function handle(Request $request, callable $next, mixed $role = null): mixed
    {
        if ($this->inExceptPaths($request->uri())) {
            return $next($request);
        }

        [$maxAttempts, $decaySeconds] = $this->resolveLimits($role);
        $key = $this->resolveKey($request, $role);

        if ($this->limiter->tooManyAttempts($key, $maxAttempts)) {
            return $this->buildThrottleResponse($request, $key, $maxAttempts);
        }

        $attempts = $this->limiter->hit($key, $decaySeconds);
        $remaining = max(0, $maxAttempts - $attempts);

        $response = $next($request);

        if ($response instanceof Response) {
            $response->header('X-RateLimit-Limit', (string) $maxAttempts);
            $response->header('X-RateLimit-Remaining', (string) $remaining);
        }

        return $response;
    }

    protected function resolveLimits(mixed $role): array
    {
        if (is_string($role) && preg_match('/^\s*(\d+)\s*,\s*(\d+)\s*$/', $role, $m)) {
            return [(int) $m[1], (int) $m[2]];
        }

        return [$this->maxAttempts, $this->decaySeconds];
    }

    protected function resolveKey(Request $request, mixed $role): string
    {
        if (is_callable($role)) {
            $key = $role($request);

            if (is_string($key) && $key !== '') {
                return $key;
            }
        }

        $ip = $this->requestIp($request);
        $email = $request->input('email');
        $identity = $ip . '|' . $request->method() . '|' . $request->uri();

        if (is_string($email) && $email !== '') {
            $identity .= '|email:' . strtolower(trim($email));
        }

        return sha1($identity);
    }

    protected function requestIp(Request $request): string
    {
        $xff = $request->header('X-Forwarded-For');

        if (is_string($xff) && $xff !== '') {
            $parts = array_map('trim', explode(',', $xff));

            if (!empty($parts[0])) {
                return $parts[0];
            }
        }

        $realIp = $request->header('X-Real-IP');

        if (is_string($realIp) && $realIp !== '') {
            return trim($realIp);
        }

        $all = $request->all();
        $server = is_array($all['server'] ?? null) ? $all['server'] : [];

        return (string) ($server['REMOTE_ADDR'] ?? '0.0.0.0');
    }

    protected function buildThrottleResponse(Request $request, string $key, int $maxAttempts): Response
    {
        $retryAfter = $this->limiter->availableIn($key);
        $headers = [
            'Retry-After' => (string) $retryAfter,
            'X-RateLimit-Limit' => (string) $maxAttempts,
            'X-RateLimit-Remaining' => '0',
        ];

        if ($request->wantsJson()) {
            return Response::json(['message' => 'Too Many Requests'], 429, $headers);
        }

        return new Response('Too Many Requests', 429, array_merge(['Content-Type' => 'text/plain; charset=utf-8'], $headers));
    }

    protected function inExceptPaths(string $uri): bool
    {
        $path = ltrim($uri, '/');

        foreach ($this->exceptPaths as $pattern) {
            $pattern = ltrim((string) $pattern, '/');

            if ($pattern === '') {
                continue;
            }

            if ($pattern === $path) {
                return true;
            }

            if (str_contains($pattern, '*')) {
                $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';

                if (preg_match($regex, $path) === 1) {
                    return true;
                }
            }
        }

        return false;
    }
}
