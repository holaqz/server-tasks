<?php

namespace App\DTO;

class DatabaseInfoDTO
{
    public string $database;
    public string $host;
    public string $username;

    public function __construct(string $database, string $host, string $username)
    {
        $this->database = $database;
        $this->host = $host;
        $this->username = $username;
    }
}