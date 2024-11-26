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
                                INSERT INTO notifications (userGuid, courseGuid)
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
                            if (is_numeric($data['mark']) and $data['mark'] >= 0.0 and $data['mark'] <= 5.3) {
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
                                echo json_encode(["error" => "mark может принимать значения от 0.0 до 5.3"]);
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

} else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // TODO: Удаление преподавателей
} else {
    echo json_encode(["message" => "Метод не поддерживается (нужен GET/POST/PUT/DELETE)"]);
}
?>