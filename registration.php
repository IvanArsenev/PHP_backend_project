<?php

require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use Ramsey\Uuid\Guid\Guid;

$config = include 'config.php';

header('Content-Type: application/json');

try {
    $pdo = new PDO(
        "mysql:host={$config['db_host']};dbname={$config['db_name']};charset={$config['db_charset']}",
        $config['db_user'],
        $config['db_password']
    );
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Ошибка подключения: " . $e->getMessage());
}

// Проверка на сильный пароль (Регулярное выраждение взято из интернета)
function isStrongPassword($password)
{
    return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password);
}

function generateGuid()
{
    return Guid::uuid4()->toString();
}

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


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    $fullName = $data['fullName'] ?? null;
    $birthDate = $data['birthDate'] ?? null;
    $email = $data['email'] ?? null;
    $password = $data['password'] ?? null;
    $confirmPassword = $data['confirmPassword'] ?? null;

    $errors = [];

    // Проверки

    if ($birthDate) {
        $dateObj = DateTime::createFromFormat('d-m-Y', $birthDate);
        if ($dateObj) {
            $birthDate = $dateObj->format('Y-m-d');
        } else {
            $errors[] = "Некорректная дата рождения.";
        }
    }
    if (!$fullName) $errors[] = "Полное имя обязательно.";
    if (!$birthDate || strtotime($birthDate) > strtotime('today')) $errors[] = "Некорректная дата рождения.";
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Некорректный email.";
    if ($password !== $confirmPassword) $errors[] = "Пароли не совпадают.";
    if (!isStrongPassword($password)) $errors[] = "Пароль должен быть сильным (минимум 8 символов, одна заглавная буква, одна цифра и специальный символ).";

    if (!$errors) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetchColumn() > 0) {
            $errors[] = "Пользователь с таким email уже существует.";
        }
    }

    if ($errors) {
        http_response_code(400);
        echo json_encode(["errors" => $errors]);
        exit;
    }

    $userGuid = generateGuid();
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    $token = generateJwt($userGuid, $config['secret_key'], $config['encoder_type']);

    $stmt = $pdo->prepare("
        INSERT INTO users (userGuid, name, birthDate, email, password, token)
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([$userGuid, $fullName, $birthDate, $email, $hashedPassword, $token]);

    echo json_encode(["token" => $token]);
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен POST)"]);
}

?>