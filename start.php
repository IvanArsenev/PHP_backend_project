<?php

require 'vendor/autoload.php';

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

function createUsersTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS users (
            userGuid CHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            birthDate DATE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            token CHAR(255) NOT NULL,
            registrationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
            admin BOOLEAN DEFAULT FALSE
        )
    ";
    $pdo->exec($query);
}

function createGroupsTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS `groups` (
            groupGuid CHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL
        )
    ";
    $pdo->exec($query);
}

function createCoursesTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS courses (
            courseGuid CHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            startYear INT NOT NULL,
            maximumStudentsCount INT NOT NULL,
            remainingSlotsCount INT NOT NULL,
            status ENUM('Created', 'OpenForAssigning', 'Started', 'Finished') NOT NULL,
            semester ENUM('Autumn', 'Spring') NOT NULL,
            requirements TEXT NOT NULL,
            annotations TEXT NOT NULL,
            mainTeacherId CHAR(36),
            groupGuid CHAR(36),
            FOREIGN KEY (mainTeacherId) REFERENCES users(userGuid),
            FOREIGN KEY (groupGuid) REFERENCES `groups`(groupGuid)
        )
    ";
    $pdo->exec($query);
}

function createStudentsTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS students (
            userGuid CHAR(36) NOT NULL,
            courseGuid CHAR(36) NOT NULL,
            status ENUM('InQueue', 'Accepted', 'Declined') NOT NULL,
            midtermResult ENUM('NotDefined', 'Passed', 'Failed') NOT NULL DEFAULT 'NotDefined',
            finalResult ENUM('NotDefined', 'Passed', 'Failed') NOT NULL DEFAULT 'NotDefined',
            FOREIGN KEY (userGuid) REFERENCES users(userGuid),
            FOREIGN KEY (courseGuid) REFERENCES courses(courseGuid),
            INDEX (userGuid),
            INDEX (courseGuid)
        )
    ";
    $pdo->exec($query);
}


function createTeachersTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS teachers (
            userGuid CHAR(36),
            courseGuid CHAR(36),
            FOREIGN KEY (userGuid) REFERENCES users(userGuid),
            FOREIGN KEY (courseGuid) REFERENCES courses(courseGuid)
        )
    ";
    $pdo->exec($query);
}

function createNotificationsTable($pdo)
{
    $query = "
        CREATE TABLE IF NOT EXISTS notifications (
            courseGuid CHAR(36),
            text TEXT NOT NULL,
            isImportant BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (courseGuid) REFERENCES courses(courseGuid)
        )
    ";
    $pdo->exec($query);
}

function createTriggerForRemainingSlots($pdo) // Триггер для уменьшения и увеличения свободных мест при записи
{
    $insertQuery = "
        CREATE TRIGGER updateRemainingSlotsAfterInsert AFTER INSERT ON students
        FOR EACH ROW
        BEGIN
            UPDATE courses
            SET remainingSlotsCount = remainingSlotsCount - 1
            WHERE courseGuid = NEW.courseGuid;
        END
    ";
    $pdo->exec($insertQuery);
    $deleteQuery = "
        CREATE TRIGGER updateRemainingSlotsAfterDelete AFTER DELETE ON students
        FOR EACH ROW
        BEGIN
            UPDATE courses
            SET remainingSlotsCount = remainingSlotsCount + 1
            WHERE courseGuid = OLD.courseGuid;
        END
    ";
    $pdo->exec($deleteQuery);
}

createUsersTable($pdo);
createGroupsTable($pdo);
createCoursesTable($pdo);
createStudentsTable($pdo);
createTeachersTable($pdo);
createNotificationsTable($pdo);
createTriggerForRemainingSlots($pdo);

?>