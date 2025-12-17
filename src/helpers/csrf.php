<?php

use Codemonster\Security\Csrf\CsrfTokenManager;

if (!function_exists('csrf_token')) {
    function csrf_token(): string
    {
        return (new CsrfTokenManager())->token();
    }
}

if (!function_exists('csrf_field')) {
    function csrf_field(): string
    {
        $token = htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8');

        return '<input type="hidden" name="_token" value="' . $token . '">';
    }
}

