# API документация
 

## Account запросы
 

### Регистрация
 

    POST http://host/registration

Пример тела запроса:
 

    {
        "fullName": "Имя пользователя",
        "birthDate": "ДД-ММ-ГГГГ",
        "email": "email@domain.domain",
        "password": "STRONG_PASSWORD",
        "confirmPassword": "STRONG_PASSWORD"
    }

Валидация:
 

    1. Проверка наличия всех полей
    2. Проверка зарегистрированного пользователя с таким email
    3. Проверка даты рождения (дата рождения не может быть позже сегодняшней даты)
    4. Проверка формата email
    5. Проверка совпадения паролей
    6. Проверка сложности пароля (минимум 8 символов, одна заглавная буква, одна цифра и специальный символ)

В случае успеха возвращает:
 

    {
        "token": "ТОКЕН ПОЛЬЗОВАТЕЛЯ" (токен живет 1 час)
    }

---
 

### Вход
 

    POST http://host/login

Пример тела запроса:
 

    {
        "email": "email@domain.domain",
        "password": "STRONG_PASSWORD"
    }

Валидация:
 

    1. Проверка наличия всех полей
    2. Проверка зарегистрированного пользователя с таким email
    3. Проверка пароля

В случае успеха возвращает:
 

    {
        "token": "ТОКЕН ПОЛЬЗОВАТЕЛЯ" (токен живет 1 час)
    }

---
 

### Выход
 

    POST http://host/logout (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    {
        "message": "Вы успешно вышли из системы."
    }

<br>
 
---
 

### Просмотр профиля
 

    GET http://host/profile (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    {
        "name": "Имя пользователя",
        "email": "email@domain.domain",
        "birthDate": "ДД-ММ-ГГГГ",
    }

---
 

### Изменение профиля
 

    PUT http://host/profile (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "fullName": "НОВОЕ ИМЯ",
        "birthDate": "ДД-ММ-ГГГГ"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка наличия полей в теле запроса
    3. Проверка даты рождения (дата рождения не может быть позже сегодняшней даты)

В случае успеха возвращает:
 

    {
        "message": "Данные пользователя успешно обновлены."
    }

---
 

## Работа с группами
 

### Просмотр групп
 

    GET http://host/groups (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    [
        {
            "id": "GUID группы",
            "name": "Имя группы"
        },
        {
            "id": "GUID группы",
            "name": "Имя группы"
        }, ...
    ]

---
 

### Создание группы
 

    POST http://host/groups (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "groupName": "ИМЯ ГРУППЫ"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка прав (создавать группы может только администратор)
    3. Проверка названия группы (1 название = 1 группа)

В случае успеха возвращает:
 

    {
        "id": "GUID группы",
        "name": "Имя группы"
    }

---
 

### Изменение группы
 

    PUT http://host/groups/{id} (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "groupName": " НОВОЕ ИМЯ ГРУППЫ"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка прав (редактировать группы может только администратор)
    3. Проверка названия группы (1 название = 1 группа)

В случае успеха возвращает:
 

    {
        "message": "Данные группы успешно обновлены."
    }

---
 

### Удаление группы
 

    DELETE http://host/groups/{id} (Выполняется с Bearer Token)

Валидация:
 

    1. Проверка корректности токена
    2. Проверка прав (удалять группы может только администратор)

В случае успеха возвращает:
 

    {
        "message": "Группа успешно удалена"
    }

---
 

### Просмотр курсов группы
 

    GET http://host/groups/{id} (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    [
        {
            "id": "GUID курса",
            "name": "Имя курса",
            "startYear": ГГГГ,
            "maximumStudentsCount": N,
            "remainingSlotsCount": N,
            "status": "Статус курса",
            "semester": "Семестр"
        }, ...
    ]

---
 

## Работа с курсами
 

### Просмотр деталей курса
 

    GET http://host/courses/{id}/details (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    {
        "id": "GUID курса",
        "name": "Имя курса",
        "startYear": ГГГГ,
        "maximumStudentsCount": N,
        "studentsEnrolledCount": N,
        "studentsInQueueCount": N,
        "requirements": "Требования",
        "annotations": "Аннотации",
        "status": "Статус",
        "semester": "Семестр",
        "students": [
            {
                "name": "Имя студента",
                "email": "email@domain.domain"
            }, ...
        ],
        "teachers": [
            {
                "name": "Имя преподавателя",
                "email": "email@domain.domain",
                "isMain": true
            }, ...
        ],
        "notifications": [
            {
                "text": "Текст уведомления",
                "isImportant": true
            }, ...
        ]
    }

---
 

### Изменение статуса курса
 

    POST http://host/courses/{id}/status (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "status": "Статус"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка полей тела запроса
    3. Статус может быть только: 'OpenForAssigning', 'Started', 'Finished'
    4. Проверка прав доступа. Менять статус могут только преподаватели данного курса или администраторы

В случае успеха возвращает:
 

    {
        "message": "Статус успешно обновлен."
    }

---
 

### Создание уведомлений курса
 

    POST http://host/courses/{id}/notifications (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "text": "Текст уведомления",
        "isImportant": true
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка полей тела запроса
    3. isImportant может быть только: true или false
    4. Проверка прав доступа. Создавать уведомления могут только преподаватели данного курса или администраторы

В случае успеха возвращает:
 

    {
        "id": "GUID курса",
        "name": "Имя курса",
        "startYear": ГГГГ,
        "maximumStudentsCount": N,
        "studentsEnrolledCount": N,
        "studentsInQueueCount": N,
        "requirements": "Требования",
        "annotations": "Аннотации",
        "status": "Статус",
        "semester": "Семестр",
        "students": [
            {
                "name": "Имя студента",
                "email": "email@domain.domain"
            }, ...
        ],
        "teachers": [
            {
                "name": "Имя преподавателя",
                "email": "email@domain.domain",
                "isMain": true
            }, ...
        ],
        "notifications": [
            {
                "text": "Текст уведомления",
                "isImportant": true
            }, ...
        ]
    }

---
 

### Добавление преподавателей курса
 

    POST http://host/courses/{id}/teachers (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
      "userId": "GUID пользователя"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка полей тела запроса
    3. Проверить, существует ли пользователь с таким GUID
    4. Проверка прав доступа. Добавлять преподавателей могут только администраторы
    5. Является ли преподаватель уже преподавателем

В случае успеха возвращает:
 

    "teachers": [
        {
            "name": "Имя преподавателя",
            "email": "email@domain.domain",
            "isMain": true
        }, ...
    ]

---
 

### Регистрация на курс
 

    POST http://host/courses/{id}/sign-up (Выполняется с Bearer Token)

Валидация:
 

    1. Проверка корректности токена
    2. Является ли пользователь преподавателем
    3. Проверить, существует ли курс таким GUID
    4. Подана ли заявка ранее

В случае успеха возвращает:
 

    {
        "message": "Заявка на курс отправлена"
    }

---
 

### Изменение статуса
 

    POST http://host/courses/{id}/student-status/{id} (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
      "status": "Статус"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка полей тела запроса
    3. Проверка статуса. Может быть только 'Accepted', 'Declined'
    4. Проверить, существует ли студент на курсе с таким GUID
    5. Проверить, существует ли курс с таким GUID
    6. Проверка прав. Изменять статус может только преподаватель курса или администратор

В случае успеха возвращает:
 

    {
        "message": "Статус успешно обновлен."
    }

---
 

### Поставить оценку студенту
 

    POST http://host/courses/{id}/marks/{id} (Выполняется с Bearer Token)

Пример тела запроса:
 

    {
        "markType": "тип оценки",
        "mark": "оценка"
    }

Валидация:
 

    1. Проверка корректности токена
    2. Проверка полей тела запроса
    3. Проверка типа оценки. Может быть только 'Midterm', 'Final'
    4. Проверить, существует ли студент на курсе с таким GUID
    5. Проверить, существует ли курс с таким GUID
    6. Проверка прав. Выставлять оценки может только преподаватель курса или администратор
    7. Оценка может принимать значения от 0.0 до 5.3

В случае успеха возвращает:
 

    {
        "message": "Оценка успешно обновлена."
    }

---
 

### Просмотр курсов, где пользователь студент
 

    GET http://host/courses/my (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    [
        {
            "id": "GUID курса",
            "name": "Имя курса",
            "startYear": ГГГГ,
            "maximumStudentsCount": N,
            "remainingSlotsCount": N,
            "status": "Статус курса",
            "semester": "Семестр"
        }, ...
    ]

---
 

### Просмотр курсов, где пользователь преподаватель
 

    GET http://host/courses/teaching (Выполняется с Bearer Token)

Валидация:
 

    Проверка корректности токена

В случае успеха возвращает:
 

    [
        {
            "id": "GUID курса",
            "name": "Имя курса",
            "startYear": ГГГГ,
            "maximumStudentsCount": N,
            "remainingSlotsCount": N,
            "status": "Статус курса",
            "semester": "Семестр"
        }, ...
    ]