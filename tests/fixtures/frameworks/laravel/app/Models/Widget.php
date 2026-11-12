<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

final class Widget extends Model
{
    protected $fillable = ['name'];

    public $timestamps = false;
}
