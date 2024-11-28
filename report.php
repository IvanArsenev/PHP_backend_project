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
        if ($user['admin'] == true) {
            $stmt = $pdo->prepare("SELECT DISTINCT mainTeacherId FROM courses");
            $stmt->execute();
            $courseGuidsMainTeacher = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $response = [];
            foreach ($courseGuidsMainTeacher as $mainTeacherGuid) {
                $stmt = $pdo->prepare("SELECT DISTINCT `name` FROM users WHERE userGuid = :userGuid");
                $stmt->execute(['userGuid' => $mainTeacherGuid]);
                $teacherName = $stmt->fetchAll(PDO::FETCH_COLUMN);
                $report = [];
                $stmt = $pdo->prepare("SELECT courseGuid, `name` FROM courses WHERE mainTeacherId = :userGuid");
                $stmt->execute(['userGuid' => $mainTeacherGuid]);
                $coursesData = $stmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($coursesData as $course) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND `status` = 'Accepted'");
                    $stmt->execute(['courseGuid' => $course['courseGuid']]);
                    $studentsCount = $stmt->fetchColumn();
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND finalResult = 'Passed' AND `status` = 'Accepted'");
                    $stmt->execute(['courseGuid' => $course['courseGuid']]);
                    $passed = $stmt->fetchColumn();
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND finalResult = 'Failed' AND `status` = 'Accepted'");
                    $stmt->execute(['courseGuid' => $course['courseGuid']]);
                    $failed = $stmt->fetchColumn();
                    if ($studentsCount == 0) {
                        $resultPassed = 0;
                        $resultFailed = 0;
                    } else {
                        $resultPassed = $passed/$studentsCount;
                        $resultFailed = $failed/$studentsCount;
                    }
                    $report[] = [
                        'name' => $course['name'],
                        'id' => $course['courseGuid'],
                        'averagePassed' => $resultPassed,
                        'averageFailed' => $resultFailed
                    ];
                }
                $response[] = [
                    'fullName' => $teacherName[0],
                    'id' => $mainTeacherGuid,
                    'campusGroupReports' => $report,
                ];
            }
            echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        } else {
            http_response_code(403);
            echo json_encode(["message" => "У Вас нет прав на генерацию отчета. Обратитесь к администратору"]);
            exit;
        }
    } else {
        echo json_encode(["error" => "В GET запросе не должно быть тела запроса"]);
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET)"]);
}
?>