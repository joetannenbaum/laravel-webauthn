<?php

namespace LaravelWebAuthn\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\ValidationException;
use LaravelWebAuthn\Ceremonies\Registration;

class RegistrationController extends Controller
{
    public function generateOptions(Request $request)
    {
        return Registration::options($request->input('username'));
    }

    public function verify()
    {
        try {
            $user = Registration::verify();
        } catch (ValidationException $e) {
            // TODO: Validate specific exceptions here
            // throw ValidationException::withMessages([
            //     'username' => 'Invalid response',
            // ]);

            return $e->errors();
        }

        auth()->login($user);

        return [
            'verified' => true,
        ];
    }
}
