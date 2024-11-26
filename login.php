<?php

require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

$config = include 'config.php';

header('Content-Type: application/json');


function generateJwt($userGuid, $secretKey, $encoderType)
{
    $issuedAt = time();
    $expirationTime = $issuedAt + 113600; // TODO: Сократить время до 3600
    $payload = array(
        "iss" => "etbx.ru",
        "iat" => $issuedAt,
        "exp" => $expirationTime,
        "userGuid" => $userGuid
    );

    return JWT::encode($payload, $secretKey, $encoderType);
}

try {
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset={$config['db_charset']}",
        $config['db_user'],
        $config['db_password']
    );
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Ошибка подключения к базе данных']);
    exit();
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['email']) || !isset($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Email и пароль обязательны']);
        exit();
    }

    $email = $data['email'];
    $password = $data['password'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['error' => 'Некорректный формат email']);
        exit();
    }

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Пользователь с таким email не найден']);
        exit();
    }

    if (!password_verify($password, $user['password'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Неверный пароль']);
        exit();
    }

    $token = generateJwt($user["userGuid"], $config['secret_key'], $config['encoder_type']);

    $updateStmt = $pdo->prepare("UPDATE users SET token = :token WHERE email = :email");
    $updateStmt->execute(['token' => $token, 'email' => $email]);

    echo json_encode(['token' => $token]);
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен POST)"]);
}
?>