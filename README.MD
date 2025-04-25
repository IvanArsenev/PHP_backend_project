# 📚 API Documentation
## 📂 Database Structure
<p align="center"> <img src="https://github.com/IvanArsenev/PHP_backend_project/blob/main/img/base_backend.png?raw=true" /> </p>

## 👤 Account Endpoints
### 🔐 Registration

```
POST http://host/registration
```

#### Example Request Body
```
{
  "fullName": "User Name",
  "birthDate": "DD-MM-YYYY",
  "email": "email@domain.com",
  "password": "STRONG_PASSWORD",
  "confirmPassword": "STRONG_PASSWORD"
}
```

#### Validations
- All fields must be present
- Email must be unique
- Birthdate must not be in the future
- Email format must be valid
- Passwords must match
- Password must be strong (min. 8 characters, 1 uppercase, 1 digit, 1 special character)

#### Success Response
```
{
  "token": "USER_TOKEN" // valid for 1 hour
}
```
### 🔓 Login
```
POST http://host/login
```
#### Example Request Body
```
{
  "email": "email@domain.com",
  "password": "STRONG_PASSWORD"
}
```
#### Validations
- All fields must be present
- Email must exist
- Password must be correct

#### Success Response

```
{
  "token": "USER_TOKEN" // valid for 1 hour
}
```
### 🚪 Logout
```
POST http://host/logout (Requires Bearer Token)
```

#### Validations
- Valid token required

#### Success Response
```
{
  "message": "Вы успешно вышли из системы."
}
```
### 👁️ View Profile
```
GET http://host/profile (Requires Bearer Token)
```

#### Success Response
```
{
  "name": "User Name",
  "email": "email@domain.com",
  "birthDate": "DD-MM-YYYY"
}
```
### ✏️ Edit Profile
```
PUT http://host/profile (Requires Bearer Token)
```
#### Example Request Body
```
{
  "fullName": "NEW NAME",
  "birthDate": "DD-MM-YYYY"
}
```

#### Validations
- Valid token
- Fields must be present
- Birthdate must not be in the future

#### Success Response
```
{
  "message": "Данные пользователя успешно обновлены."
}
```

## 🧑‍🤝‍🧑 Group Management
### 📄 View Groups
```
GET http://host/groups (Requires Bearer Token)
```
#### Success Response
```
[
  {
    "id": "GROUP_GUID",
    "name": "Group Name"
  }
]
```
### ➕ Create Group
```
POST http://host/groups (Requires Bearer Token)
```
#### Example Request Body
```
{
  "groupName": "GROUP NAME"
}
```
#### Validations
- Admin only
- Unique group name
- Success Response

#### Success Response
```
{
  "id": "GROUP_GUID",
  "name": "Group Name"
}
```
### ✏️ Edit Group
```
PUT http://host/groups/{id} (Requires Bearer Token)
id = group GUID
```
#### Example Request Body
```
{
  "groupName": "NEW GROUP NAME"
}
```
#### Validations
- Admin only
- Unique group name
- Success Response

```
{
  "message": "Данные группы успешно обновлены."
}
```
### ❌ Delete Group
```
DELETE http://host/groups/{id} (Requires Bearer Token)
id = group GUID
```
#### Validations
- Admin only

#### Success Response
```
{
  "message": "Группа успешно удалена"
}
```
### 📚 View Group Courses
```
GET http://host/groups/{id} (Requires Bearer Token)
id = group GUID
```

#### Success Response
```
[
  {
    "id": "COURSE_GUID",
    "name": "Course Name",
    "startYear": 2024,
    "maximumStudentsCount": 30,
    "remainingSlotsCount": 10,
    "status": "Course Status",
    "semester": "Semester"
  }
]
```
## 📘 Course Management
### 📄 Course Details
```
GET http://host/courses/{id}/details (Requires Bearer Token)
id = course GUID
```
#### Success Response
```
{
  "id": "COURSE_GUID",
  "name": "Course Name",
  "startYear": 2024,
  "maximumStudentsCount": 30,
  "studentsEnrolledCount": 20,
  "studentsInQueueCount": 5,
  "requirements": "Requirements",
  "annotations": "Annotations",
  "status": "Status",
  "semester": "Semester",
  "students": [
    {
      "name": "Student Name",
      "email": "email@domain.com"
    }
  ],
  "teachers": [
    {
      "name": "Teacher Name",
      "email": "email@domain.com",
      "isMain": true
    }
  ],
  "notifications": [
    {
      "text": "Notification text",
      "isImportant": true
    }
  ]
}
```
### 🔄 Change Course Status
```
POST http://host/courses/{id}/status (Requires Bearer Token)
id = course GUID
```
#### Example Request Body
```
{
  "status": "OpenForAssigning"
}
```
#### Validations
- Status must be one of: OpenForAssigning, Started, Finished
- Only teachers or admins can change status

#### Success Response
```
{
  "message": "Статус успешно обновлен."
}
```
### 🔔 Add Course Notification
```
POST http://host/courses/{id}/notifications (Requires Bearer Token)
id = course GUID
```
#### Example Request Body
```
{
  "text": "Notification text",
  "isImportant": true
}
```
#### Validations
- Only teachers or admins can post notifications

#### Success Response: Same as Course Details
### 👨‍🏫 Add Course Teacher
```
POST http://host/courses/{id}/teachers (Requires Bearer Token)
id = course GUID
```
#### Example Request Body
```
{
  "userId": "USER_GUID"
}
```

#### Validations
- Admin only
- User must exist
- User must not already be a teacher

#### Success Response
```
{
  "teachers": [
    {
      "name": "Teacher Name",
      "email": "email@domain.com",
      "isMain": true
    }
  ]
}
```
### 📝 Sign Up for Course
```
POST http://host/courses/{id}/sign-up (Requires Bearer Token)
id = course GUID
```
#### Validations
- Course must exist
- Course must be open for registration
- Must not already be enrolled or waiting

#### Success Response
```
{
  "message": "Заявка на курс отправлена"
}
```

### 🔁 Update Student Status
```
POST http://host/courses/{courseId}/student-status/{studentId} (Requires Bearer Token)
```

#### Example Request Body
```
{
  "status": "Accepted"
}
```
#### Validations
- Verification of the validity of the token
- Checking the fields of the request body
- Check the status. Maybe only 'Accepted', 'Declined'
- Check if there is a student in the course with such a GUID.
- Check if there is a course with this GUID.
- Rights verification. Only the course teacher or the administrator can change the status.

#### Success Response
```
{
  "message": "Статус успешно обновлен."
}
```

### Give a student a grade

```
POST http://host/courses/{courseId}/marks/{studentId} (Requires Bearer Token)
```

#### Example Request Body
```
{
    "markType": "Midterm",
    "mark": "Passed"
}
```
#### Validations
- Verification of the validity of the token
- Checking the fields of the request body
- Checking the type of assessment. It can only be 'Midterm', 'Final'
- Check if there is a student in the course with such a GUID.
- Check if there is a course with this GUID.
- Rights verification. Only the course teacher or the administrator can give grades.
- The score can take the values 'NotDefined', 'Passed', 'Failed'
- Verification that the student is enrolled in the course

#### Success Response
```
{
  "message": "Оценка успешно обновлена."
}
```

### Viewing courses where the user is a student

```
GET http://host/courses/my (Requires Bearer Token)
```


#### Validations
- Verification of the validity of the token

#### Success Response
```
[
    {
        "id": "course GUID",
        "name": "Course name",
        "startYear": YYYY,
        "maximumStudentsCount": N,
        "remainingSlotsCount": N,
        "status": "Status",
        "semester": "Semester"
    }, ...
]
```

### Viewing courses where the user is a teacher

```
GET http://host/courses/teaching  (Requires Bearer Token)
```


#### Validations
- Verification of the validity of the token

#### Success Response
```
[
    {
        "id": "course GUID",
        "name": "Course name",
        "startYear": YYYY,
        "maximumStudentsCount": N,
        "remainingSlotsCount": N,
        "status": "Status",
        "semester": "Semester"
    }, ...
]
```

### Changing requirements and annotations

```
PUT http://host/courses/{courseId}/requirements-and-annotations (Requires Bearer Token)
```

#### Example Request Body
```
{
    "requirements": "some text",
    "annotations": "some text"
}
```
#### Validations
- Verification of the validity of the token
- Checking the requirements field
- Checking the annotations field
- Verification of the request body
- Checking access rights

#### Success Response
```
{
  "message": "Аннотации успешно обновлены."
}
```

### Course change

```
PUT http://host/courses/{courseId} (Requires Bearer Token)
```

#### Example Request Body
```
{
    "name": "name",
    "startYear": YYYY,
    "maximumStudentsCount": N,
    "semester": "semester",
    "requirements": "requirements",
    "annotations": "annotations",
    "mainTeacherId": "mainTeacherId"
}
```
#### Validations
- Verification of the validity of the token
- Checking the name field (1 name = 1 course in the group)
- Checking the startYear field (the start year is not less than the current one)
- Checking the semester field ('Autumn', 'Spring')
- Checking the requirements field
- Checking the annotations field
- Checking the mainTeacherId field (the user exists)
- Checking access rights

P.s. The maximumStudentsCount field is validated only for the condition of a positive number. The maximumStudentsCount may be less than the students in the course

#### Success Response
```
{
  "message": "Курс успешно обновлен."
}
```

### Course Deletion

```
DELETE http://host/courses/{courseId} (Requires Bearer Token)
```

#### Validations
- Verification of the validity of the token
- Checking access rights
- Checking the existence of the course

#### Success Response
```
{
  "message": "Курс, студенты курса, преподаватели курса и уведомления курса удалены!"
}
```

### Deleting a course teacher

```
DELETE http://host/courses/{courseId}/teacherId (Requires Bearer Token)
```

#### Validations
- Verification of the validity of the token
- Checking access rights
- Checking the existence of the course
- Checking the teacher's existence

#### Success Response
```
{
  "message": "Преподаватель удален."
}
```

## Reports
### Print of all users

```
GET http://host/users (Requires Bearer Token)
```

#### Validations
- Verification of the validity of the token

#### Success Response
```
[
    {
        "id": "user GUID",
        "name": "user guid",
        "email": "domain@domain.domain"
    }, ...
]
```

### Output of user roles

```
GET http://host/roles (Requires Bearer Token)
```

#### Validations
- Verification of the validity of the token

#### Success Response
```
[
    {
        "Admin": "false"
    },
    {
        "Course id": "course GUID",
        "Main teacher": false,
        "Base teacher": false,
        "Student": true
    }, ...
]
```

### Report output

```
GET http://host/report (Requires Bearer Token)
```

#### Validations
- Verification of the validity of the token
- Checking access rights

#### Success Response
```
[
    {
        "fullName": "Teacher name",
        "id": "Teacher GUID",
        "campusGroupReports": [
            {
                "name": "Course name",
                "id": "Course GUID",
                "averagePassed": N,
                "averageFailed": N
            }, ...
        ]
    },.
]
```

## The real history of commits
<p align="center">
<img src="https://github.com/IvanArsenev/PHP_backend_project/blob/main/img/real_commit_story.png?raw=true"  />
<p>
