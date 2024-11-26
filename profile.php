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

$stmt = $pdo->prepare("SELECT * FROM users WHERE userGuid = :userGuid");
$stmt->execute(['userGuid' => $userGuid]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user['token'] == '0') {
    http_response_code(401);
    echo json_encode(["message" => "Пользователь не в системе"]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (empty($data)) {
        echo json_encode(["name" => $user['name'], "email" => $user['email'], "birthDate" => $user['birthDate']]);
    } else {
        echo json_encode(["error" => "В GET запросе не должно быть тела запроса"]);
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (empty($data)) {
        echo json_encode(["error" => "В PUT запросе должно быть тело запроса"]);
    } else {
        $updates = [];
        $params = [];
        if (isset($data['fullName'])) {
            $updates[] = "name = ?";
            $params[] = $data['fullName'];
        }
        if (isset($data['birthDate'])) {
            $dateObj = DateTime::createFromFormat('d-m-Y', $data['birthDate']);
            if ($dateObj) {
                $birthDate = $dateObj->format('Y-m-d');
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Некорректный формат даты. Поддерживается: ДД-ММ-ГГГГ"]);
                exit;
            }
            if (strtotime($birthDate) > strtotime('today')){
                http_response_code(400);
                echo json_encode(["error" => "Дата рождения не может быть позже сегодняшней"]);
                exit;
            }
            $updates[] = "birthDate = ?";
            $params[] = $birthDate;
        }
        if (empty($updates)) {
            http_response_code(400);
            echo json_encode(["error" => "Должно быть указано хотя бы одно поле для обновления (fullName или birthDate)."]);
            exit;
        }
        $params[] = $userGuid;

        try {
            $sql = "UPDATE users SET " . implode(", ", $updates) . " WHERE userGuid = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            if ($stmt->rowCount() > 0) {
                echo json_encode(["message" => "Данные пользователя успешно обновлены."]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Не удалось обновить данные. Пользователь не найден или данные не изменены."]);
            }
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(["error" => "Ошибка подключения к базе данных: " . $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET или PUT)"]);
}
?>