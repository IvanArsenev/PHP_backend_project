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
    $data = json_decode(file_get_contents('php://input'), true);
    if (empty($data)) {
        if (count($urlParts) == 3 && $urlParts[count($urlParts) - 1] == "my") {
            $stmt = $pdo->prepare("SELECT courseGuid FROM students WHERE userGuid = :userGuid");
            $stmt->execute(['userGuid' => $user['userGuid']]);
            $courseGuids = $stmt->fetchAll(PDO::FETCH_COLUMN);
            if (count($courseGuids) > 0) {
                $inQuery = implode(',', array_fill(0, count($courseGuids), '?'));
                $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid IN ($inQuery)");
                $stmt->execute($courseGuids);
                $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $response = [];
                foreach ($courses as $course) {
                    $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = ? AND `status` = ?");
                    $stmtCount->execute([$course['courseGuid'], 'Accepted']);
                    $enrolledCount = $stmtCount->fetchColumn();
                    $response[] = [
                        'id' => $course['courseGuid'],
                        'name' => $course['name'],
                        'startYear' => $course['startYear'],
                        'maximumStudentsCount' => $course['maximumStudentsCount'],
                        'remainingSlotsCount' => $course['maximumStudentsCount'] - $enrolledCount,
                        'status' => $course['status'],
                        'semester' => $course['semester']
                    ];
                }
                echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } else {
                echo json_encode([], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            }
        } else if (count($urlParts) == 3 && $urlParts[count($urlParts) - 1] == "teaching") {
            $stmt = $pdo->prepare("SELECT courseGuid FROM teachers WHERE userGuid = :userGuid");
            $stmt->execute(['userGuid' => $user['userGuid']]);
            $courseGuids = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $stmt = $pdo->prepare("SELECT courseGuid FROM courses WHERE mainTeacherId = :userGuid");
            $stmt->execute(['userGuid' => $user['userGuid']]);
            $courseGuidsMain = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $allCourseGuids = array_unique(array_merge($courseGuids, $courseGuidsMain));
            if (count($allCourseGuids) > 0) {
                $inQuery = implode(',', array_fill(0, count($allCourseGuids), '?'));
                $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid IN ($inQuery)");
                $stmt->execute($allCourseGuids);
                $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $response = [];
                foreach ($courses as $course) {
                    $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = ? AND `status` = ?");
                    $stmtCount->execute([$course['courseGuid'], 'Accepted']);
                    $enrolledCount = $stmtCount->fetchColumn();
                    $response[] = [
                        'id' => $course['courseGuid'],
                        'name' => $course['name'],
                        'startYear' => $course['startYear'],
                        'maximumStudentsCount' => $course['maximumStudentsCount'],
                        'remainingSlotsCount' => $course['maximumStudentsCount'] - $enrolledCount,
                        'status' => $course['status'],
                        'semester' => $course['semester']
                    ];
                }
                echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } else {
                echo json_encode([], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            }
        } else if (count($urlParts) == 4 && $urlParts[count($urlParts) - 1] == "details") {
            $courseGuid = $urlParts[count($urlParts) - 2];
            $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
            $stmt->execute(['courseGuid' => $courseGuid]);
            $course = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($course) {
                $stmt = $pdo->prepare("SELECT COUNT(*) as enrolledCount FROM students WHERE courseGuid = :courseGuid AND status = 'Accepted'");
                $stmt->execute(['courseGuid' => $courseGuid]);
                $enrolledCount = $stmt->fetch(PDO::FETCH_ASSOC)['enrolledCount'];
                $stmt = $pdo->prepare("SELECT COUNT(*) as queueCount FROM students WHERE courseGuid = :courseGuid AND status = 'InQueue'");
                $stmt->execute(['courseGuid' => $courseGuid]);
                $queueCount = $stmt->fetch(PDO::FETCH_ASSOC)['queueCount'];
                $stmt = $pdo->prepare("SELECT u.userGuid AS id, u.name, u.email, s.status, s.midtermResult, s.finalResult FROM students s JOIN users u ON s.userGuid = u.userGuid WHERE s.courseGuid = :courseGuid");
                $stmt->execute(['courseGuid' => $courseGuid]);
                $students = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $stmt = $pdo->prepare("SELECT name, email FROM users WHERE userGuid = :teacherGuid");
                $stmt->execute(['teacherGuid' => $course['mainTeacherId']]);
                $mainTeacher = $stmt->fetch(PDO::FETCH_ASSOC);
                $mainTeacher['isMain'] = true;
                $stmt = $pdo->prepare("SELECT u.name, u.email FROM teachers t JOIN users u ON t.userGuid = u.userGuid WHERE t.courseGuid = :courseGuid AND t.userGuid != :mainTeacherId");
                $stmt->execute(['courseGuid' => $courseGuid, 'mainTeacherId' => $course['mainTeacherId']]);
                $additionalTeachers = $stmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($additionalTeachers as &$teacher) {$teacher['isMain'] = false;}
                unset($teacher);
                $teachers = array_merge([$mainTeacher], $additionalTeachers);
                $stmt = $pdo->prepare("SELECT text, isImportant FROM notifications WHERE courseGuid = :courseGuid");
                $stmt->execute(['courseGuid' => $courseGuid]);
                $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $response = [
                    'id' => $course['courseGuid'],
                    'name' => $course['name'],
                    'startYear' => $course['startYear'],
                    'maximumStudentsCount' => $course['maximumStudentsCount'],
                    'studentsEnrolledCount' => $enrolledCount,
                    'studentsInQueueCount' => $queueCount,
                    'requirements' => $course['requirements'],
                    'annotations' => $course['annotations'],
                    'status' => $course['status'],
                    'semester' => $course['semester'],
                    'students' => $students,
                    'teachers' => $teachers,
                    'notifications' => $notifications
                ];
                echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            } else {
                http_response_code(400);
                echo json_encode(["message" => "Курса с таким id не существует!"]);
                exit;
            }  
        }
    } else {
        echo json_encode(["error" => "В GET запросе не должно быть тела запроса"]);
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    if (count($urlParts) == 4) {
        $courseGuid = $urlParts[count($urlParts) - 2];
        $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
        $stmt->execute(['courseGuid' => $courseGuid]);
        $course = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($course) {
            $data = json_decode(file_get_contents('php://input'), true);
            if ($urlParts[count($urlParts) - 1] == "sign-up") {
                if ($course['status'] == "OpenForAssigning") {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                    $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                    if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                        http_response_code(400);
                        echo json_encode(["error" => "Пользователь является преподавателем данного курса"]);
                        exit;
                    } else {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                        $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                        if ($stmt->fetchColumn() > 0) {
                            http_response_code(400);
                            echo json_encode(["error" => "Пользователь уже подал заявку на курс"]);
                            exit;
                        } else {
                            $stmt = $pdo->prepare("
                                INSERT INTO students (userGuid, courseGuid, status)
                                VALUES (?, ?, ?)
                            ");
                            $stmt->execute([$user['userGuid'], $courseGuid, 'InQueue']);
                            echo json_encode(["message" => "Заявка на курс отправлена"]);
                        }
                    }
                } else {
                    http_response_code(400);
                    echo json_encode(["message" => "Запись на курс в данный момент недоступна"]);
                    exit;
                }
            } else if (empty($data)) {
                echo json_encode(["error" => "В POST запросе должно быть тело запроса"]);
            } else {
                if ($urlParts[count($urlParts) - 1] == "status") {
                    if (isset($data['status'])) {
                        if ($data['status'] == 'OpenForAssigning' or $data['status'] == 'Started' or $data['status'] == 'Finished') {
                            $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                            $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                            if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                                $sql = "UPDATE `courses` SET `status` = ? WHERE `courseGuid` = ?";
                                $stmt = $pdo->prepare($sql);
                                $stmt->execute([$data['status'], $courseGuid]);
                                if ($stmt->rowCount() > 0) {
                                    echo json_encode(["message" => "Статус успешно обновлен."]);
                                } else {
                                    http_response_code(400);
                                    echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                                }
                            } else {
                                http_response_code(403);
                                echo json_encode(["error" => "У Вас нет прав. Менять статус могут только преподаватели данного курса или администраторы!"]);
                                exit;
                            }

                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Status может принимать параметры 'OpenForAssigning', 'Started', 'Finished'"]);
                            exit;
                        }
                    } else {
                        http_response_code(400);
                        echo json_encode(["error" => "В теле запроса должен быть параметр status"]);
                        exit;
                    }
                } else if ($urlParts[count($urlParts) - 1] == "notifications") {
                    if (isset($data['text']) and isset($data['isImportant'])) {
                        if ($data['isImportant'] === true or $data['isImportant'] === false) {
                            $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                            $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                            if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                                $stmt = $pdo->prepare("
                                    INSERT INTO notifications (courseGuid, text, isImportant)
                                    VALUES (?, ?, ?)
                                ");
                                $stmt->execute([$courseGuid, $data['text'], $data['isImportant']]);
                                $stmt = $pdo->prepare("SELECT COUNT(*) as enrolledCount FROM students WHERE courseGuid = :courseGuid AND status = 'Accepted'");
                                $stmt->execute(['courseGuid' => $courseGuid]);
                                $enrolledCount = $stmt->fetch(PDO::FETCH_ASSOC)['enrolledCount'];
                                $stmt = $pdo->prepare("SELECT COUNT(*) as queueCount FROM students WHERE courseGuid = :courseGuid AND status = 'InQueue'");
                                $stmt->execute(['courseGuid' => $courseGuid]);
                                $queueCount = $stmt->fetch(PDO::FETCH_ASSOC)['queueCount'];
                                $stmt = $pdo->prepare("SELECT u.userGuid AS id, u.name, u.email, s.status, s.midtermResult, s.finalResult FROM students s JOIN users u ON s.userGuid = u.userGuid WHERE s.courseGuid = :courseGuid");
                                $stmt->execute(['courseGuid' => $courseGuid]);
                                $students = $stmt->fetchAll(PDO::FETCH_ASSOC);
                                $stmt = $pdo->prepare("SELECT name, email FROM users WHERE userGuid = :teacherGuid");
                                $stmt->execute(['teacherGuid' => $course['mainTeacherId']]);
                                $mainTeacher = $stmt->fetch(PDO::FETCH_ASSOC);
                                $mainTeacher['isMain'] = true;
                                $stmt = $pdo->prepare("SELECT u.name, u.email FROM teachers t JOIN users u ON t.userGuid = u.userGuid WHERE t.courseGuid = :courseGuid AND t.userGuid != :mainTeacherId");
                                $stmt->execute(['courseGuid' => $courseGuid, 'mainTeacherId' => $course['mainTeacherId']]);
                                $additionalTeachers = $stmt->fetchAll(PDO::FETCH_ASSOC);
                                foreach ($additionalTeachers as &$teacher) {$teacher['isMain'] = false;}
                                unset($teacher);
                                $teachers = array_merge([$mainTeacher], $additionalTeachers);
                                $stmt = $pdo->prepare("SELECT text, isImportant FROM notifications WHERE courseGuid = :courseGuid");
                                $stmt->execute(['courseGuid' => $courseGuid]);
                                $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
                                $response = [
                                    'id' => $course['courseGuid'],
                                    'name' => $course['name'],
                                    'startYear' => $course['startYear'],
                                    'maximumStudentsCount' => $course['maximumStudentsCount'],
                                    'studentsEnrolledCount' => $enrolledCount,
                                    'studentsInQueueCount' => $queueCount,
                                    'requirements' => $course['requirements'],
                                    'annotations' => $course['annotations'],
                                    'status' => $course['status'],
                                    'semester' => $course['semester'],
                                    'students' => $students,
                                    'teachers' => $teachers,
                                    'notifications' => $notifications
                                ];
                                echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                            } else {
                                http_response_code(403);
                                echo json_encode(["error" => "У Вас нет прав. Публиковать уведомления могут только преподаватели данного курса или администраторы!"]);
                                exit;
                            }
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Параметр isImportant иожет быть только true или false"]);
                            exit;
                        }
                    } else {
                        http_response_code(400);
                        echo json_encode(["error" => "В теле запроса должны быть параметры text и isImportant"]);
                        exit;
                    }
                } else if ($urlParts[count($urlParts) - 1] == "teachers" and $user['admin'] == true) {
                    if (isset($data['userId'])) {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                        $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                        if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid']) {
                            http_response_code(400);
                            echo json_encode(["error" => "Пользователь уже является преподавателем данного курса"]);
                            exit;
                        } else {
                            $stmt = $pdo->prepare("
                                INSERT INTO teachers (userGuid, courseGuid)
                                VALUES (?, ?)
                            ");
                            $stmt->execute([$data['userId'], $courseGuid]);
                            $stmt = $pdo->prepare("SELECT name, email FROM users WHERE userGuid = :teacherGuid");
                            $stmt->execute(['teacherGuid' => $course['mainTeacherId']]);
                            $mainTeacher = $stmt->fetch(PDO::FETCH_ASSOC);
                            $mainTeacher['isMain'] = true;
                            $stmt = $pdo->prepare("SELECT u.name, u.email FROM teachers t JOIN users u ON t.userGuid = u.userGuid WHERE t.courseGuid = :courseGuid AND t.userGuid != :mainTeacherId");
                            $stmt->execute(['courseGuid' => $courseGuid, 'mainTeacherId' => $course['mainTeacherId']]);
                            $additionalTeachers = $stmt->fetchAll(PDO::FETCH_ASSOC);
                            foreach ($additionalTeachers as &$teacher) {$teacher['isMain'] = false;}
                            unset($teacher);
                            $teachers = array_merge([$mainTeacher], $additionalTeachers);
                            echo json_encode(['teachers' => $teachers]);
                        }
                    } else {
                        http_response_code(400);
                        echo json_encode(["error" => "В теле запроса должен быть параметр userId"]);
                        exit;
                    }
                } else {
                    http_response_code(404);
                    echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
                    exit;
                }
            }
        } else {
            http_response_code(400);
            echo json_encode(["message" => "Курса с таким id не существует!"]);
            exit;
        } 
    } else if (count($urlParts) == 5) {
        $courseGuid = $urlParts[count($urlParts) - 3];
        $studentGuid = $urlParts[count($urlParts) - 1];
        $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
        $stmt->execute(['courseGuid' => $courseGuid]);
        $course = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt = $pdo->prepare("SELECT * FROM students WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
        $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $studentGuid]);
        $student = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($course and $student) {
            $data = json_decode(file_get_contents('php://input'), true);
            if ($urlParts[count($urlParts) - 2] == "student-status") {
                if (isset($data['status'])) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                    $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                    if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                        $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $studentGuid]);
                        $sql = "UPDATE `students` SET `status` = ? WHERE `courseGuid` = ? AND `userGuid` = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$data['status'], $courseGuid, $studentGuid]);
                        if ($stmt->rowCount() > 0) {
                            echo json_encode(["message" => "Статус успешно обновлен."]);
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                        }
                    } else {
                        http_response_code(400);
                        echo json_encode(["error" => "У Вас нет прав на выполнение данного запроса!"]);
                        exit; 
                    }
                } else {
                    http_response_code(400);
                    echo json_encode(["error" => "В теле запроса должен быть параметр status ('Accepted', 'Declined')"]);
                    exit;
                }
            } else if ($urlParts[count($urlParts) - 2] == "marks") {
                if (isset($data['markType']) and isset($data['mark'])) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                    $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                    if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                        if ($data['markType'] == 'Midterm' or $data['markType'] == 'Final') {
                            if ($data['mark'] == 'NotDefined' or $data['mark'] == 'Passed' or $data['mark'] == 'Failed') {
                                if ($data['markType'] == 'Midterm') {
                                    $sql = "UPDATE `students` SET midtermResult = ? WHERE `courseGuid` = ? AND `userGuid` = ?";
                                    $stmt = $pdo->prepare($sql);
                                    $stmt->execute([$data['mark'], $courseGuid, $studentGuid]);
                                } else {
                                    $sql = "UPDATE `students` SET finalResult = ? WHERE `courseGuid` = ? AND `userGuid` = ?";
                                    $stmt = $pdo->prepare($sql);
                                    $stmt->execute([$data['mark'], $courseGuid, $studentGuid]);
                                }
                                if ($stmt->rowCount() > 0) {
                                    echo json_encode(["message" => "Оценка успешно обновлена."]);
                                } else {
                                    http_response_code(400);
                                    echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                                }
                            } else {
                                http_response_code(400);
                                echo json_encode(["error" => "mark может принимать значения 'NotDefined', 'Passed', 'Failed'"]);
                                exit;
                            }
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "markType может быть только Midterm и Final"]);
                            exit;
                        }
                    } else {
                        http_response_code(400);
                        echo json_encode(["error" => "У Вас нет прав на выполнение данного запроса!"]);
                        exit; 
                    }
                } else {
                    http_response_code(400);
                    echo json_encode(["error" => "В теле запроса должны быть параметры markType и mark"]);
                    exit;
                }
            } else {
                http_response_code(404);
                echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
                exit;
            }
        } else {
            http_response_code(400);
            echo json_encode(["message" => "Курса или студента на курсе с таким id не существует!"]);
            exit;
        }
    } else {
        http_response_code(404);
        echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
        exit;
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    if (count($urlParts) == 4) {
        $courseGuid = $urlParts[count($urlParts) - 2];
    } else {
        $courseGuid = $urlParts[count($urlParts) - 1];
    }
    $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
    $stmt->execute(['courseGuid' => $courseGuid]);
    $course = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($course) {
        $data = json_decode(file_get_contents('php://input'), true);
        if (empty($data)) {
            echo json_encode(["error" => "В POST запросе должно быть тело запроса"]);
        } else {
            if (count($urlParts) == 4 and $urlParts[count($urlParts) - 1] == "requirements-and-annotations") {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $user['userGuid']]);
                if ($stmt->fetchColumn() > 0 or $course['mainTeacherId'] == $user['userGuid'] or $user['admin'] == true) {
                    $requirements = $data['requirements'] ?? null;
                    $annotations = $data['annotations'] ?? null;
                    $errors = [];
                    if (strlen($requirements)>1023) {
                        $errors[] = "Поле требования не может быть длинее 1023 символов.";
                    }
                    if (strlen($annotations)>1023) {
                        $errors[] = "Поле аннотации не может быть длинее 1023 символов.";
                    }
                    if ($errors) {
                        http_response_code(400);
                        echo json_encode(["errors" => $errors]);
                        exit;
                    }
                    if (!$requirements and !$annotations) {
                        http_response_code(400);
                        echo json_encode(["errors" => "Выберите параметры для изменения (requirements или annotations)"]);
                        exit;
                    } else if (!$requirements) {
                        $sql = "UPDATE `courses` SET `annotations` = ? WHERE `courseGuid` = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$data['annotations'], $courseGuid]);
                        if ($stmt->rowCount() > 0) {
                            echo json_encode(["message" => "Аннотации успешно обновлены."]);
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                        }
                    } else if (!$annotations) {
                        $sql = "UPDATE `courses` SET `requirements` = ? WHERE `courseGuid` = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$data['requirements'], $courseGuid]);
                        if ($stmt->rowCount() > 0) {
                            echo json_encode(["message" => "Требования успешно обновлены."]);
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                        }
                    } else {
                        $sql = "UPDATE `courses` SET `requirements` = ?, `annotations` = ? WHERE `courseGuid` = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$data['requirements'], $data['annotations'], $courseGuid]);
                        if ($stmt->rowCount() > 0) {
                            echo json_encode(["message" => "Требования и аннотации успешно обновлены."]);
                        } else {
                            http_response_code(400);
                            echo json_encode(["error" => "Не удалось обновить данные. Курс не найден или данные не изменены."]);
                        }
                    }
                } else {
                    http_response_code(404);
                    echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
                    exit;
                }
            } else if (count($urlParts) == 3) {
                if ($user['admin'] == true) {
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
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM courses WHERE `name` = ? AND groupGuid = ?");
                        $stmt->execute([$name, $course['groupGuid']]);
                        if ($stmt->fetchColumn() > 0) {
                            $errors[] = "Курс с таким именем в группе уже существует.";
                        }
                    }
                    if ($errors) {
                        http_response_code(400);
                        echo json_encode(["errors" => $errors]);
                        exit;
                    }
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                    $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $mainTeacherId]);
                    if ($stmt->fetchColumn() > 0) {
                        $stmt = $pdo->prepare("DELETE FROM teachers WHERE userGuid = ?");
                        $stmt->execute([$mainTeacherId]);
                    }
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM students WHERE courseGuid = :courseGuid AND userGuid = :userGuid");
                    $stmt->execute(['courseGuid' => $courseGuid, 'userGuid' => $mainTeacherId]);
                    if ($stmt->fetchColumn() > 0) {
                        $stmt = $pdo->prepare("DELETE FROM students WHERE userGuid = ?");
                        $stmt->execute([$mainTeacherId]);
                    }
                    if ($mainTeacherId != $course['mainTeacherId']) {
                        $stmt = $pdo->prepare("
                            INSERT INTO teachers (userGuid, courseGuid)
                            VALUES (?, ?)
                        ");
                        $stmt->execute([$mainTeacherId, $courseGuid]);
                    }
                    $stmt = $pdo->prepare("
                        UPDATE courses SET name = ?, startYear = ?, maximumStudentsCount = ?, semester = ?, requirements = ?, annotations = ?, mainTeacherId = ?
                        WHERE courseGuid = ?
                    ");
                    $stmt->execute([$name, $startYear, $maximumStudentsCount, $semester, $requirements, $annotations, $mainTeacherId, $courseGuid]);
                    echo json_encode(["message" => "Курс успешно обновлен."]);
                } else {
                    http_response_code(404);
                    echo json_encode(["message" => "У Вас нет прав для выполнения действия. Обратитесь к администратору!"]);
                    exit;
                }
            } else {
                http_response_code(404);
                echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
                exit;
            }
        }
    } else {
        http_response_code(404);
        echo json_encode(["message" => "Такого курса не существует или у Вас нет прав!"]);
        exit;
    }
} else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $urlParts = explode('/', $_SERVER['REQUEST_URI']);
    if (count($urlParts) == 3) {
        $courseGuid = $urlParts[count($urlParts) - 1];
        $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
        $stmt->execute(['courseGuid' => $courseGuid]);
        $course = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($course and $user['admin'] == true) {
            $data = json_decode(file_get_contents('php://input'), true);
            if (empty($data)) {
                $stmt = $pdo->prepare("DELETE FROM teachers WHERE courseGuid = ?");
                $stmt->execute([$courseGuid]);
                $stmt = $pdo->prepare("DELETE FROM students WHERE courseGuid = ?");
                $stmt->execute([$courseGuid]);
                $stmt = $pdo->prepare("DELETE FROM notifications WHERE courseGuid = ?");
                $stmt->execute([$courseGuid]);
                $stmt = $pdo->prepare("DELETE FROM courses WHERE courseGuid = ?");
                $stmt->execute([$courseGuid]);
                echo json_encode(["message" => "Курс, студенты курса, преподаватели курса и уведомления курса удалены!"]);
            } else {
                echo json_encode(["error" => "В DELETE запросе не должно быть тела запроса"]);
            }
        } else {
            http_response_code(404);
            echo json_encode(["message" => "Такого курса не существует или у Вас нет прав!"]);
            exit;
        }
    } else if (count($urlParts) == 4) {
        $courseGuid = $urlParts[count($urlParts) - 2];
        $stmt = $pdo->prepare("SELECT * FROM courses WHERE courseGuid = :courseGuid");
        $stmt->execute(['courseGuid' => $courseGuid]);
        $course = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($course and $user['admin'] == true) {
            $teacherGuid = $urlParts[count($urlParts) - 1];
            $stmt = $pdo->prepare("SELECT * FROM teachers WHERE courseGuid = :courseGuid AND userGuid = :teacherGuid");
            $stmt->execute(['courseGuid' => $courseGuid, 'teacherGuid' => $teacherGuid]);
            $teacher = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($teacher) {
                $stmt = $pdo->prepare("DELETE FROM teachers WHERE courseGuid = ? AND userGuid = ?");
                $stmt->execute([$courseGuid, $teacherGuid]);
                echo json_encode(["message" => "Преподаватель удален."]);
            } else {
                http_response_code(404);
                echo json_encode(["message" => "Преподаватель не найден. Можно удалить только не главного преподавателя."]);
                exit;
            }
        } else {
            http_response_code(404);
            echo json_encode(["message" => "Такого курса не существует или у Вас нет прав!"]);
            exit;
        }
    } else {
        http_response_code(404);
        echo json_encode(["message" => "Такого эндпоинта не существует или у Вас нет прав!"]);
        exit;
    }
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET/POST/PUT/DELETE)"]);
}
?>