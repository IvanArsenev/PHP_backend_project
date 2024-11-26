<?php

require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Ramsey\Uuid\Guid\Guid;

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

function generateGuid()
{
    return Guid::uuid4()->toString();
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
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    $groupGuid = $urlParts[count($urlParts) - 1];
    $data = json_decode(file_get_contents('php://input'), true);
    if (empty($data)) {
        if ($groupGuid != 'groups') {
            try {
                $stmt = $pdo->prepare("SELECT courseGuid AS id, name, startYear, maximumStudentsCount, remainingSlotsCount, `status`, semester FROM courses WHERE groupGuid = ?");
                $stmt->execute([$groupGuid]);
                $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($groups, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } catch (PDOException $e) {
                http_response_code(500);
                echo json_encode(['error' => 'Ошибка выполнения запроса к базе данных']);
            }
        } else {
            try {
                $stmt = $pdo->query("SELECT groupGuid AS id, name FROM `groups`");
                $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($groups, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } catch (PDOException $e) {
                http_response_code(500);
                echo json_encode(['error' => 'Ошибка выполнения запроса к базе данных']);
            }
        }
    } else {
        echo json_encode(["error" => "В GET запросе не должно быть тела запроса"]);
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    $groupGuid = $urlParts[count($urlParts) - 1];
    if ($user['admin'] == true) {
        $data = json_decode(file_get_contents('php://input'), true);
        if (empty($data)) {
            echo json_encode(["error" => "В POST запросе должно быть тело запроса"]);
        } else {
            if ($groupGuid != 'groups') {
                $name = $data['name'] ?? null;
                $startYear = $data['startYear'] ?? null;
                $maximumStudentsCount = $data['maximumStudentsCount'] ?? null;
                $semester = $data['semester'] ?? null;
                $requirements = $data['requirements'] ?? null;
                $annotations = $data['annotations'] ?? null;
                $mainTeacherId = $data['mainTeacherId'] ?? null;
                $errors = [];
                if (!$name) $errors[] = "Поле имя обязательно.";
                if (!$startYear) $errors[] = "Дата начала курса обязательна.";
                if (!$maximumStudentsCount) $errors[] = "Укажите максимальное количество студентов.";
                if (!$semester) $errors[] = "Поле семестр обязательно.";
                if (!$requirements) $errors[] = "Поле требования обязательно.";
                if (!$annotations) $errors[] = "Поле аннотации обязательно.";
                if (!$mainTeacherId) $errors[] = "Укажите основного преподавателя.";
                $currentYear = (int)date('Y'); 
                if (!filter_var($startYear, FILTER_VALIDATE_INT) || $startYear < $currentYear) {
                    $errors[] = "Поле дата начала курса можеть быть годом, начиная от текущего.";
                }
                if (!filter_var($maximumStudentsCount, FILTER_VALIDATE_INT) || $maximumStudentsCount > 1000000 || $maximumStudentsCount < 1) {
                    $errors[] = "Поле максимальное количество студентов не может быть больше 1 000 000.";
                }
                if ($semester != "Autumn" and $semester != "Spring") {
                    $errors[] = "Поле семестр может принимать значения Autumn и Spring.";
                }
                if (strlen($requirements)>1023) {
                    $errors[] = "Поле требования не может быть длинее 1023 символов.";
                }
                if (strlen($annotations)>1023) {
                    $errors[] = "Поле аннотации не может быть длинее 1023 символов.";
                }
                if (!$errors) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE userGuid = ?");
                    $stmt->execute([$mainTeacherId]);
                    if ($stmt->fetchColumn() == 0) {
                        $errors[] = "Пользователь с таким guid не существует.";
                    }
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM `groups` WHERE groupGuid = ?");
                    $stmt->execute([$groupGuid]);
                    if ($stmt->fetchColumn() == 0) {
                        $errors[] = "Группы с таким guid не существует.";
                    }
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM courses WHERE `name` = ? AND groupGuid = ?");
                    $stmt->execute([$name, $groupGuid]);
                    if ($stmt->fetchColumn() > 0) {
                        $errors[] = "Курс с таким именем в группе уже существует.";
                    }
                }
                $courseGuid = generateGuid();
                if ($errors) {
                    http_response_code(400);
                    echo json_encode(["errors" => $errors]);
                    exit;
                }
                $stmt = $pdo->prepare("
                    INSERT INTO courses (courseGuid, name, startYear, maximumStudentsCount, remainingSlotsCount, status, semester, requirements, annotations, mainTeacherId, groupGuid)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([$courseGuid, $name, $startYear, $maximumStudentsCount, $maximumStudentsCount, "Created", $semester, $requirements, $annotations, $mainTeacherId, $groupGuid]);

                $stmt = $pdo->prepare("SELECT courseGuid AS id, name, startYear, maximumStudentsCount, remainingSlotsCount, `status`, semester FROM courses WHERE groupGuid = ?");
                $stmt->execute([$groupGuid]);
                $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($groups, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } else {
                if (isset($data['groupName'])) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM `groups` WHERE `name` = ?");
                    $stmt->execute([$data['groupName']]);
                    if ($stmt->fetchColumn() > 0) {
                        http_response_code(400);
                        echo json_encode(["error" => "Группа с таким названием уже существует!"]);
                        exit;
                    } else {
                        $groupGuid = generateGuid();
                        $stmt = $pdo->prepare("
                            INSERT INTO `groups` (groupGuid, name)
                            VALUES (?, ?)
                        ");
                        $stmt->execute([$groupGuid, $data['groupName']]);
                        echo json_encode(["id" => $groupGuid, "name" => $data['groupName']]);
                    }
                } else {
                    http_response_code(400);
                    echo json_encode(["error" => "В теле запроса должен быть параметр groupName"]);
                    exit;
                }
            }
        }
    } else {
        http_response_code(403);
        echo json_encode(["error" => "Вы не можете создавать группы. Обратитесь к администратору!"]);
        exit;
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    $groupGuid = $urlParts[count($urlParts) - 1];
    if ($user['admin'] == true) {
        $data = json_decode(file_get_contents('php://input'), true);
        if (empty($data)) {
            echo json_encode(["error" => "В PUT запросе должно быть тело запроса"]);
        } else {
            if (isset($data['groupName'])) {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM `groups` WHERE `name` = ?");
                $stmt->execute([$data['groupName']]);
                if ($stmt->fetchColumn() > 0) {
                    http_response_code(400);
                    echo json_encode(["error" => "Группа с таким названием уже существует!"]);
                    exit;
                } else {
                    try {
                        $sql = "UPDATE `groups` SET `name` = ? WHERE `groupGuid` = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$data['groupName'], $groupGuid]);
                        if ($stmt->rowCount() > 0) {
                            echo json_encode(["message" => "Данные группы успешно обновлены."]);
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Не удалось обновить данные. Группа не найдена или данные не изменены."]);
                        }
                    } catch (PDOException $e) {
                        http_response_code(500);
                        echo json_encode(["error" => "Ошибка подключения к базе данных: " . $e->getMessage()]);
                    }
                }
            } else {
                http_response_code(400);
                echo json_encode(["error" => "В теле запроса должен быть параметр groupName"]);
                exit;
            }
        }
    } else {
        http_response_code(403);
        echo json_encode(["error" => "Вы не можете изменять группы. Обратитесь к администратору!"]);
        exit;
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    $groupGuid = $urlParts[count($urlParts) - 1];
    $data = json_decode(file_get_contents('php://input'), true);
    if (empty($data)) {
        if ($user['admin'] == true) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM `groups` WHERE groupGuid = ?");
            $stmt->execute([$groupGuid]);
            if ($stmt->fetchColumn() > 0) {
                $stmt = $pdo->prepare("SELECT * FROM courses WHERE groupGuid = :groupGuid");
                $stmt->execute(['groupGuid' => $groupGuid]);
                $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($courses as $course) {
                    $courseGuid = $course['courseGuid'];
                    $stmt = $pdo->prepare("DELETE FROM teachers WHERE courseGuid = ?");
                    $stmt->execute([$courseGuid]);
                    $stmt = $pdo->prepare("DELETE FROM students WHERE courseGuid = ?");
                    $stmt->execute([$courseGuid]);
                    $stmt = $pdo->prepare("DELETE FROM notifications WHERE courseGuid = ?");
                    $stmt->execute([$courseGuid]);
                }
                $stmt = $pdo->prepare("DELETE FROM courses WHERE groupGuid = ?");
                $stmt->execute([$groupGuid]);
                $stmt = $pdo->prepare("DELETE FROM `groups` WHERE groupGuid = ?");
                $stmt->execute([$groupGuid]);
                if ($stmt->rowCount() > 0) {
                    http_response_code(200);
                    echo json_encode(["message" => "Группа успешно удалена"]);
                } else {
                    http_response_code(500);
                    echo json_encode(["error" => "Не удалось удалить группу"]);
                }
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Группы с таким id не существует!"]);
                exit;
            }
        } else {
            http_response_code(403);
            echo json_encode(["error" => "Вы не можете изменять группы. Обратитесь к администратору!"]);
            exit;
        }
    } else {
        echo json_encode(["error" => "В DELETE запросе не должно быть тела запроса"]);
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET/POST/PUT/DELETE)"]);
}
?>