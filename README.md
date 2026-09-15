# 🎓 Campus-Connect

Campus-Connect is a web-based **student attendance management system** built with Python and Flask. It provides a centralized platform for students, faculty, and administrators to manage attendance, monitor student records, conduct attendance sessions, and handle attendance correction requests.

The system is designed to make classroom attendance more organized, accessible, and easier to manage compared with manual attendance processes.

## ✨ Key Features

### 👨‍🎓 Student Features

- Secure student login
- View personal attendance records
- View attendance by subject
- Mark attendance during active faculty sessions
- Attendance verification using session codes
- Submit attendance correction requests
- Receive notifications and messages regarding attendance
- Change account password

### 👨‍🏫 Faculty Features

- Faculty login and role-based access
- Start attendance sessions for subjects
- Generate temporary attendance codes
- Track attendance during active sessions
- View student information
- Review attendance correction requests
- Approve or reject correction requests
- Maintain faculty session history

### 🛡️ Administrator Features

- Administrator login
- Add and manage student and faculty accounts
- Manage user roles
- Access student and faculty information
- Manage attendance-related data
- Review correction requests

## 📊 Attendance Management

Campus-Connect uses a session-based attendance mechanism.

Faculty can start an attendance session for a subject, which generates a temporary verification code. Students can use the active session to mark their attendance.

The system also prevents duplicate attendance records within the same session and maintains subject-wise attendance information.

## 📝 Attendance Correction

Students can submit a correction request when their attendance needs to be reviewed.

The request is assigned to the appropriate faculty member, who can:

- Review the request
- Approve the correction
- Reject the correction

When a request is processed, the student receives a corresponding notification.

## 🔐 Role-Based Access

The application provides different access levels for:

- **Student**
- **Faculty**
- **Administrator**

Access to different operations is controlled according to the user's role.

## 🛠️ Technologies Used

### Backend
- **Python**
- **Flask**
- **SQLite**

### Frontend
- **HTML5**
- **CSS3**
- **JavaScript**

### Deployment
- **Render**

## 📁 Project Structure

```text
Campus-Connect/
│
├── app.py
├── index.html
├── dashboard.html
├── script.js
├── style.css
├── database.db
├── requirements.txt
├── render.yaml
└── .gitignore
````

## ⚙️ How It Works

```text
                    Campus-Connect
                          │
          ┌───────────────┼───────────────┐
          │               │               │
       Student          Faculty          Admin
          │               │               │
          ▼               ▼               ▼
     Login / View    Start Session     Manage Users
     Attendance      Generate Code     Manage Data
          │               │               │
          └───────────────┼───────────────┘
                          │
                          ▼
                    Flask Backend
                          │
                          ▼
                     SQLite Database
```

## 🚀 Running the Project Locally

### 1. Clone the repository

```bash
git clone https://github.com/vedaabdhija/Campus-Connect.git
```

### 2. Navigate to the project directory

```bash
cd Campus-Connect
```

### 3. Install the required dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Flask application

```bash
python app.py
```

### 5. Open the application

Open the local address provided by Flask in your browser.

## 🎯 Project Objective

The objective of Campus-Connect is to provide a centralized digital platform for managing student attendance and related academic workflows.

The project demonstrates the use of:

* Web application development
* Flask-based backend development
* Database management with SQLite
* Role-based access control
* Attendance session management
* Frontend and backend integration
* Deployment configuration

## 🔮 Future Improvements

Possible future enhancements include:

* PostgreSQL or other production-grade database support
* Advanced attendance analytics
* Attendance reports and exports
* Email or push notifications
* Improved authentication and security
* Mobile application support
* Automated deployment and testing

## 👩‍💻 Developed By

**Veda Abdhija**

Computer Science Engineering Graduate
