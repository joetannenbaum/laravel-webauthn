<?php

use Cose\Algorithms;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;

return [
    'user_model' => App\Models\User::class,

    'username_field' => 'email',

    'relying_party' => [
        'name' => env('APP_NAME'),
        'id'   => env('APP_URL'),
    ],

    // TODO: Timeout config
    // https://webauthn-doc.spomky-labs.com/pure-php/authenticate-your-users

    // Session key for registration
    'credential_create_options_session_key' => 'webauthn_public_key_credential_creation_options',

    // Session key for authentication
    // TODO: Do these need to be different? Nest under "session" key if so
    'credential_request_options_session_key' => 'webauthn_public_key_credential_request_options',

    'supported_algorithms' => [
        Algorithms::COSE_ALGORITHM_ES256,
        Algorithms::COSE_ALGORITHM_ES256K,
        Algorithms::COSE_ALGORITHM_ES384,
        Algorithms::COSE_ALGORITHM_ES512,
        Algorithms::COSE_ALGORITHM_RS256,
        Algorithms::COSE_ALGORITHM_RS384,
        Algorithms::COSE_ALGORITHM_RS512,
        Algorithms::COSE_ALGORITHM_PS256,
        Algorithms::COSE_ALGORITHM_PS384,
        Algorithms::COSE_ALGORITHM_PS512,
        Algorithms::COSE_ALGORITHM_ED256,
        Algorithms::COSE_ALGORITHM_ED512,
    ],

    // TODO: Make these names human and explain what is going on
    // https://w3c.github.io/webauthn/#dictionary-authenticatorSelection
    'authenticator_selection_criteria' => [
        // https://w3c.github.io/webauthn/#enum-residentKeyRequirement
        'resident_key' => AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
        // https://w3c.github.io/webauthn/#enum-attachment
        'authenticator_attachment' => AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
    ],

    // https://w3c.github.io/webauthn/#enum-attestation-convey
    'attestation_conveyance_preference' => PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,

    // https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension
    'authenticator_credential_properties_extension' => [
        'cred_props' => true,
    ],

];
