<?php

namespace LaravelWebAuthn\Ceremonies;

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;

trait CreatesAttestationManagers
{
    protected static function createAttestationManager(): AttestationStatementSupportManager
    {
        $attestationManager = AttestationStatementSupportManager::create();
        $attestationManager->add(NoneAttestationStatementSupport::create());

        return $attestationManager;
    }
}
