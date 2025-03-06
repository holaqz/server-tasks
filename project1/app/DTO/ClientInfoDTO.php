<?php

namespace App\DTO;

class ClientInfoDTO
{
    public string $ip;
    public string $user_agent;

    public function __construct(string $ip, string $user_agent)
    {
        $this->ip = $ip;
        $this->user_agent = $user_agent;
    }
}