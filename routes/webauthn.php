<?php

use Illuminate\Support\Facades\Route;
use LaravelWebAuthn\Http\Controllers\AuthenticationController;
use LaravelWebAuthn\Http\Controllers\RegistrationController;

Route::group(['prefix' => 'webauthn', 'middleware' => ['web']], function () {
    Route::prefix('register')->controller(RegistrationController::class)->group(function () {
        Route::post('options', 'generateOptions')->name('webauthn.register.options');
        Route::post('verify', 'verify')->name('webauthn.register.verify');
    });

    Route::prefix('auth')->controller(AuthenticationController::class)->group(function () {
        Route::post('options', 'generateOptions')->name('webauthn.auth.options');
        Route::post('verify', 'verify')->name('webauthn.auth.verify');
    });
});
