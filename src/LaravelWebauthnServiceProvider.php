<?php

namespace LaravelWebAuthn;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LaravelWebauthnServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-webauthn')
            ->hasConfigFile()
            // ->hasViews()
            // ->hasMigration('create_laravel-webauthn_table')
            // ->hasCommand(LaravelWebauthnCommand::class)
            ->hasRoutes('webauthn');
    }
}
