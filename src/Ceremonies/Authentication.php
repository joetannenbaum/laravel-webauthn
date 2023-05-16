<?php

namespace LaravelWebAuthn\Ceremonies;

use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Manager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\ValidationException;
use LaravelWebAuthn\Repositories\CredentialSource;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use Spatie\StructureDiscoverer\Discover;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class Authentication
{
    public static function options(Model $user)
    {
        // User Entity
        $userEntity = PublicKeyCredentialUserEntity::create(
            $user[config('webauthn.username_field')],
            $user->webauthn_id,
            $user[config('webauthn.username_field')],
            // TODO: Icon? data:image/png;base64,xxxx
        );

        // A repo of our public key credentials
        $pkSourceRepo = new CredentialSource();

        // A user can have multiple authenticators, so we need to get all of them to check against
        $registeredAuthenticators = $pkSourceRepo->findAllForUserEntity($userEntity);

        // We don’t need the Credential Sources, just the associated Descriptors
        $allowedCredentials = collect($registeredAuthenticators)
            ->pluck('public_key')
            ->map(
                fn ($publicKey) => PublicKeyCredentialSource::createFromArray($publicKey)
            )
            ->map(
                fn (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor()
            )
            ->toArray();

        $pkRequestOptions = PublicKeyCredentialRequestOptions::create(
            random_bytes(32) // Challenge
        )
            ->setRpId(parse_url(config('webauthn.relying_party.id'), PHP_URL_HOST))
            // Tell the device which authenticators we are allowed to use
            ->allowCredentials(...$allowedCredentials);
        // TODO: Accommodate?
        //         ->setUserVerification(
        //     PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
        // )
        //     ->addExtension(
        //     AuthenticationExtension::create('loc', true),
        //     AuthenticationExtension::create('txAuthSimple', 'Please log in with a registered authenticator'),
        // )

        $serializedOptions = $pkRequestOptions->jsonSerialize();

        // It is important to store the the options object in the session
        // for the next step. The data will be needed to check the response from the device.
        session()->put(
            config('webauthn.credential_request_options_session_key'),
            // TODO: Security issue? I'm storing this in the session as a backup for
            // authenticators that do not return the user handle in the response
            [$user->webauthn_id, $serializedOptions],
        );

        return $serializedOptions;
    }

    public static function verify()
    {
        $serverRequest = app(ServerRequestInterface::class);

        // This is a repo of our public key credentials
        $pkSourceRepo = new CredentialSource();

        $attestationManager = AttestationStatementSupportManager::create();
        $attestationManager->add(NoneAttestationStatementSupport::create());

        $selectedAlgos = collect(config('webauthn.supported_algorithms'));

        $allAlgos = collect(
            Discover::in(base_path('vendor/web-auth/cose-lib'))
                ->classes()
                ->implementing(Algorithm::class)
                ->get()
        )
            ->filter(fn ($alg) => with(new ReflectionClass($alg))->isInstantiable())
            ->filter(fn ($alg) => $selectedAlgos->contains($alg::identifier()));

        $algorithmManager = Manager::create()->add(
            ...$allAlgos->map(fn ($alg) => $alg::create())->toArray(),
        );

        // The validator that will check the response from the device
        $responseValidator = AuthenticatorAssertionResponseValidator::create(
            $pkSourceRepo,
            IgnoreTokenBindingHandler::create(),
            ExtensionOutputCheckerHandler::create(),
            $algorithmManager,
        );

        // A loader that will load the response from the device
        $pkCredentialLoader = PublicKeyCredentialLoader::create(
            AttestationObjectLoader::create($attestationManager)
        );

        $publicKeyCredential = $pkCredentialLoader->loadArray(request()->all());

        $authenticatorAssertionResponse = $publicKeyCredential->getResponse();

        if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
            throw ValidationException::withMessages([
                'username' => 'Invalid response type',
            ]);
        }

        [$userHandle, $options] = session()->pull(config('webauthn.credential_request_options_session_key'));

        $pkRequestOptions = PublicKeyCredentialRequestOptions::createFromArray($options);

        // Check the response from the device, this will
        // throw an exception if the response is invalid.
        // For the purposes of this demo, we are letting
        // the exception bubble up so we can see what is
        // going on.
        $publicKeyCredentialSource = $responseValidator->check(
            $publicKeyCredential->getRawId(),
            $authenticatorAssertionResponse,
            $pkRequestOptions,
            $serverRequest,
            $authenticatorAssertionResponse->getUserHandle() ?? $userHandle,
        );

        // If we've gotten this far, the response is valid!
        $model = config('webauthn.user_model');

        return $model::where('webauthn_id', $publicKeyCredentialSource->getUserHandle())->firstOrFail();
    }
}
