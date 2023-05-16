<?php

namespace LaravelWebAuthn\Ceremonies;

use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;

trait LoadsPublicKeyCredentials
{
    use CreatesAttestationManagers;

    protected static function loadPublicKeyCredentials(): PublicKeyCredential
    {
        // A loader that will load the response from the device
        $pkCredentialLoader = PublicKeyCredentialLoader::create(
            AttestationObjectLoader::create(self::createAttestationManager())
        );

        return $pkCredentialLoader->loadArray(request()->all());
    }
}
