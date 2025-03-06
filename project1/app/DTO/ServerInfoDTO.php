<?php

namespace App\DTO;

class ServerInfoDTO
{
    public string $php_version;

    public function __construct(string $php_version)
    {
        $this->php_version = $php_version;
    }
}