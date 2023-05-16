<?php

namespace LaravelWebAuthn\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use LaravelWebAuthn\LaravelWebauthnServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'LaravelWebAuthn\\LaravelWebauthn\\Database\\Factories\\' . class_basename($modelName) . 'Factory'
        );
    }

    public function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testing');

        /*
        $migration = include __DIR__.'/../database/migrations/create_laravel-webauthn_table.php.stub';
        $migration->up();
        */
    }

    protected function getPackageProviders($app)
    {
        return [
            LaravelWebauthnServiceProvider::class,
        ];
    }
}
