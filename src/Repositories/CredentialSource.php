<?php

namespace LaravelWebAuthn\Repositories;

use LaravelWebAuthn\Models\Authenticator;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

class CredentialSource implements PublicKeyCredentialSourceRepository
{
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $authenticator = Authenticator::where(
            'credential_id',
            base64_encode($publicKeyCredentialId)
        )->first();

        if (!$authenticator) {
            return null;
        }

        return PublicKeyCredentialSource::createFromArray($authenticator->public_key);
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $model = config('webauthn.user_model');

        return $model::with('authenticators')
            ->where('webauthn_id', $publicKeyCredentialUserEntity->getId())
            ->first()
            ->authenticators
            ->makeVisible('public_key')
            ->makeVisible('credential_id')
            ->toArray();
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $model = config('webauthn.user_model');

        $user = $model::where(
            'webauthn_id',
            $publicKeyCredentialSource->getUserHandle()
        )->firstOrFail();

        $exists = $user->authenticators()->where(
            'credential_id',
            base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId())
        )->where(
            'public_key',
            json_encode($publicKeyCredentialSource->jsonSerialize())
        )->exists();

        if (!$exists) {
            $user->authenticators()->save(new Authenticator([
                'credential_id' => $publicKeyCredentialSource->getPublicKeyCredentialId(),
                'public_key'    => $publicKeyCredentialSource->jsonSerialize(),
            ]));
        }
    }
}
