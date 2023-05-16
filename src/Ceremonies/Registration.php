<?php

namespace LaravelWebAuthn\Ceremonies;

use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use LaravelWebAuthn\Repositories\CredentialSource;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class Registration
{
    public static function options(string $identifier)
    {
        // Relying Party Entity i.e. the application
        $rpEntity = PublicKeyCredentialRpEntity::create(
            config('webauthn.relying_party.name'),
            parse_url(config('webauthn.relying_party.id'), PHP_URL_HOST),
            // TODO: icon?
        );

        $authenticatorId = Str::uuid()->toString();

        // User Entity
        $userEntity = PublicKeyCredentialUserEntity::create(
            $identifier,
            $authenticatorId,
            $identifier,
            null,
        );

        // Challenge (random binary string)
        $challenge = random_bytes(32);

        // List of supported public key parameters
        $supportedPublicKeyParams = collect(config('webauthn.supported_algorithms'))->map(
            fn ($algorithm) => PublicKeyCredentialParameters::create('public-key', $algorithm)
        )->toArray();

        // Instantiate PublicKeyCredentialCreationOptions object
        $pkCreationOptions =
            PublicKeyCredentialCreationOptions::create(
                $rpEntity,
                $userEntity,
                $challenge,
                $supportedPublicKeyParams,
            )
                ->setAttestation(config('webauthn.attestation_conveyance_preference'))
                ->setAuthenticatorSelection(
                    AuthenticatorSelectionCriteria::create()
                        ->setResidentKey(
                            config('webauthn.authenticator_selection_criteria.resident_key'),
                        )->setAuthenticatorAttachment(
                            config('webauthn.authenticator_selection_criteria.authenticator_attachment')
                        )
                )
                ->setExtensions(
                    AuthenticationExtensionsClientInputs::createFromArray([
                        'credProps' => config(
                            'webauthn.authenticator_credential_properties_extension.cred_props'
                        ),
                    ])
                );

        $serializedOptions = $pkCreationOptions->jsonSerialize();

        if (!isset($serializedOptions['excludeCredentials'])) {
            // TODO: Config?
            // The JS side needs this, so let's set it up for success with an empty array
            $serializedOptions['excludeCredentials'] = [];
        }

        // This library for some reason doesn't serialize the extensions object,
        // so we'll do it manually
        if (!isset($serializedOptions['extensions'])) {
            $serializedOptions['extensions'] = [];
        } elseif (!is_array($serializedOptions['extensions'])) {
            // TODO: Config
            $serializedOptions['extensions'] = $serializedOptions['extensions']->jsonSerialize();
        }

        // It is important to store the user entity and the options object in the session
        // for the next step. The data will be needed to check the response from the device.
        session()->put(
            config('webauthn.credential_create_options_session_key'),
            $serializedOptions
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

        // The validator that will check the response from the device
        $responseValidator = AuthenticatorAttestationResponseValidator::create(
            $attestationManager,
            $pkSourceRepo,
            IgnoreTokenBindingHandler::create(),
            ExtensionOutputCheckerHandler::create(),
        );

        // A loader that will load the response from the device
        $pkCredentialLoader = PublicKeyCredentialLoader::create(
            AttestationObjectLoader::create($attestationManager)
        );

        $publicKeyCredential = $pkCredentialLoader->load(json_encode(request()->all()));

        $authenticatorAttestationResponse = $publicKeyCredential->getResponse();

        if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
            throw ValidationException::withMessages([
                'username' => 'Invalid response type',
            ]);
        }

        // We don't need the options anymore, so let's remove them from the session
        $pkCreationOptions = PublicKeyCredentialCreationOptions::createFromArray(
            session()->pull(config('webauthn.credential_create_options_session_key'))
        );

        // Check the response from the device, this will
        // throw an exception if the response is invalid.
        // For the purposes of this demo, we are letting
        // the exception bubble up so we can see what is
        // going on.
        $publicKeyCredentialSource = $responseValidator->check(
            $authenticatorAttestationResponse,
            $pkCreationOptions,
            $serverRequest
        );

        // If we've gotten this far, the response is valid!

        // Save the user and the public key credential source to the database
        $model = config('webauthn.user_model');
        $field = config('webauthn.username_field');

        $user = $model::create([
            $field        => $pkCreationOptions->getUser()->getName(),
            'webauthn_id' => $publicKeyCredentialSource->getUserHandle(),
        ]);

        $pkSourceRepo->saveCredentialSource($publicKeyCredentialSource);

        return $user;
    }
}
