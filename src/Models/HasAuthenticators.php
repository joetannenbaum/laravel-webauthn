<?php

namespace LaravelWebAuthn\Models;

trait HasAuthenticators
{
    public function authenticators()
    {
        return $this->hasMany(Authenticator::class);
    }
}
