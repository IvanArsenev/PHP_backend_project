<?php

require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use Firebase\JWT\Key;

$config = include 'config.php';

header('Content-Type: application/json');

function getTokenFromRequest() {
    $headers = apache_request_headers();
    if (isset($headers['Authorization'])) {
        return str_replace('Bearer ', '', $headers['Authorization']);
    }
    return null;
}

function decodeJwt($jwt, $secretKey, $encoder_type)
{
    try{
        return JWT::decode($jwt, new Key($secretKey, $encoder_type));
    } catch (Exception $e) {
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = getTokenFromRequest();
    if (!$token) {
        http_response_code(400);
        echo json_encode(["error" => "Где токен?"]);
        exit;
    }

    $decoded = decodeJwt($token, $config['secret_key'], $config['encoder_type']);
    if (!$decoded) {
        http_response_code(401);
        echo json_encode(["error" => "Неверный токен."]);
        exit;
    }

    $userGuid = $decoded->userGuid;

    try {
        $pdo = new PDO(
            "mysql:host={$config['db_host']};dbname={$config['db_name']};charset={$config['db_charset']}",
            $config['db_user'],
            $config['db_password']
        );
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $stmt = $pdo->prepare("UPDATE users SET token = '0' WHERE userGuid = ?");
        $stmt->execute([$userGuid]);
        if ($stmt->rowCount() > 0) {
            echo json_encode(["message" => "Вы успешно вышли из системы."]);
        } else {
            http_response_code(400);
            echo json_encode(["error" => "Не удалось выйти. Пользователь не найден."]);
        }
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(["error" => "Ошибка подключения к базе данных: " . $e->getMessage()]);
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен POST)"]);
}
?>
