<?php

namespace LaravelWebAuthn\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Authenticator extends Model
{
    use HasFactory;

    protected $fillable = [
        'credential_id',
        'public_key',
    ];

    protected $hidden = [
        'credential_id',
        'public_key',
    ];

    protected $casts = [
        'public_key'    => 'json',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function credentialId(): Attribute
    {
        return new Attribute(
            get: fn ($value) => base64_decode($value),
            set: fn ($value) => base64_encode($value),
        );
    }
}
