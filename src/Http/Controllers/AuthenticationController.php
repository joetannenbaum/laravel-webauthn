<?php

namespace LaravelWebAuthn\Http\Controllers;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\ValidationException;
use LaravelWebAuthn\Ceremonies\Authentication;

class AuthenticationController extends Controller
{
    public function generateOptions(Request $request)
    {
        try {
            $model = config('webauthn.user_model');
            $user = $model::where(config('webauthn.username_field'), $request->input('username'))->firstOrFail();
            // TODO: Also check if they have registered authenticators
        } catch (ModelNotFoundException $e) {
            throw ValidationException::withMessages([
                'username' => 'User not found',
            ]);
        }

        return Authentication::options($user);
    }

    public function verify()
    {
        $user = Authentication::verify();

        auth()->login($user);

        return [
            'verified' => true,
        ];
    }
}
