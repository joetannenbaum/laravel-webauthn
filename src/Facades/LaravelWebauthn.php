<?php

namespace LaravelWebAuthn\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \LaravelWebAuthn\LaravelWebauthn
 */
class LaravelWebauthn extends Facade
{
    protected static function getFacadeAccessor()
    {
        return \LaravelWebAuthn\LaravelWebauthn::class;
    }
}
