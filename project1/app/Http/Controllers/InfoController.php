<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class InfoController extends Controller
{
    public function serverInfo(): JsonResponse
    {
        $data = [
            'php_version' => phpversion(),
        ];
        return response()->json($data);
    }

    public function clientInfo(Request $request): JsonResponse
    {
        $data = [
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ];
        return response()->json($data);
    }

    public function databaseInfo(): JsonResponse
    {
        $data = [
            'database' => config('database.connections.mysql.database'),
            'username' => config('database.connections.mysql.username'),
            'host' => config('database.connections.mysql.host'),
        ];
        return response()->json($data);
    }

}