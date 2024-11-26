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
        $response = [];
        if ($user['admin'] == true) {
            $response[] = ["Admin" => "true"];
        } else {
            $response[] = ["Admin" => "false"];
        }
        $stmt = $pdo->prepare("SELECT courseGuid FROM students WHERE userGuid = :userGuid");
        $stmt->execute(['userGuid' => $user['userGuid']]);
        $courseGuidsStudent = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $stmt = $pdo->prepare("SELECT courseGuid FROM teachers WHERE userGuid = :userGuid");
        $stmt->execute(['userGuid' => $user['userGuid']]);
        $courseGuidsTeacher = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $allCourseGuids = array_unique(array_merge($courseGuidsStudent, $courseGuidsTeacher));
        if (count($allCourseGuids) > 0) {
            $inQuery = implode(',', array_fill(0, count($courseGuidsStudent), '?'));
            $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid IN ($inQuery)");
            $stmt->execute($courseGuidsStudent);
            $coursesStudent = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $inQuery = implode(',', array_fill(0, count($courseGuidsTeacher), '?'));
            $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid IN ($inQuery)");
            $stmt->execute($courseGuidsTeacher);
            $coursesTeacher = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($coursesStudent as $course) {
                $response[] = [
                    'id' => $course['courseGuid'],
                    'teacher' => false,
                    'student' => true
                ];
            }
            foreach ($coursesTeacher as $course) {
                $response[] = [
                    'id' => $course['courseGuid'],
                    'teacher' => true,
                    'student' => false
                ];
            }
            echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        } else {
            echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        }
    } else {
        echo json_encode(["error" => "В GET запросе не должно быть тела запроса"]);
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET)"]);
}
?>