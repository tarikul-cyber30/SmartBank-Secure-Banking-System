# 🏦 SmartBank – Secure File-Based Banking System

A secure console-based banking application developed in **C++11** using **Object-Oriented Programming (OOP)** principles. SmartBank simulates real-world banking operations while integrating modern cybersecurity mechanisms including **custom SHA-256 password hashing with per-user salt**, **XOR-encrypted persistent storage**, **OTP-based Multi-Factor Authentication (MFA)**, **account lockout**, **ATM card blocking**, **administrator authentication**, **audit logging**, and **transaction history management**.

---

# 📖 Executive Summary

SmartBank v2.2 is a secure banking simulation developed for academic purposes that combines Object-Oriented Programming with practical cybersecurity concepts.

The application provides three major banking environments:

- 🏧 ATM Banking
- 🌐 Online Banking
- 👨‍💼 Administrative Management

Unlike traditional console banking projects, SmartBank securely stores user data using encrypted persistent storage, protects passwords with SHA-256 hashing and unique salts, verifies sensitive operations using simulated OTP authentication, maintains audit logs, and supports account approval workflows.

---

# 🎯 Objectives

## Primary Objectives

- Develop a secure banking system using C++ and OOP
- Demonstrate secure authentication mechanisms
- Protect user credentials using SHA-256 with per-user salt
- Store banking data securely using encrypted file storage
- Simulate practical banking security controls
- Implement administrative management and audit logging

## Secondary Objectives

- Demonstrate layered security
- Implement persistent file-based storage
- Maintain auditability and accountability
- Keep the project portable and dependency-free
- Provide a scalable architecture for future enhancements

---

# ✨ Key Features

## 👤 Customer Banking

- New Account Registration
- Secure Login
- Deposit Funds
- Withdraw Funds
- Money Transfer
- Balance Inquiry
- Transaction History
- Utility Bill Payment

---

## 🏧 ATM Services

- PIN Authentication
- OTP Verification
- Daily Withdrawal Limit
- Automatic Card Blocking
- Card Unblocking (Admin)

---

## 👨‍💼 Administration

- Master Password Authentication
- Review Pending Applications
- Approve / Reject Accounts
- Unlock User Accounts
- Unblock ATM Cards
- View Registered Customers
- View Audit Logs
- Monitor Transactions

---

## 💾 Data Management

- Persistent Storage
- Automatic Database Loading
- Automatic Database Saving
- Secure File Encryption

---

# 🔐 Security Features

SmartBank implements multiple layers of security.

- ✅ Custom SHA-256 Password Hashing
- ✅ Per-User Random Salt
- ✅ Salted Password Verification
- ✅ XOR-Encrypted Database Files
- ✅ OTP-Based Multi-Factor Authentication
- ✅ Account Lock after Multiple Failed Login Attempts
- ✅ ATM Card Blocking after Incorrect PIN Attempts
- ✅ Administrator Password Hashing
- ✅ Security Audit Logging
- ✅ Transaction Logging
- ✅ Exception Handling
- ✅ Persistent Secure Storage

---

# 🧠 Object-Oriented Programming Concepts

| Concept | Implementation |
|----------|----------------|
| Encapsulation | Protects sensitive account, card and user data |
| Abstraction | Banking and security modules separated into classes |
| Inheritance | Extendable system architecture |
| Polymorphism | Flexible transaction processing |
| Composition | Bank, User, Card and Security modules |
| Exception Handling | Runtime error protection |

---

# 🏗 System Architecture

```text
                User
                  │
                  ▼
         Console Interface
                  │
                  ▼
      Main Banking Application
                  │
      ┌───────────┼───────────┐
      ▼           ▼           ▼
 ATM Module   Online Bank   Admin Panel
      │           │           │
      └───────────┼───────────┘
                  ▼
          Security System
                  │
      ┌───────────┼────────────┐
      ▼           ▼            ▼
 SHA-256     OTP Engine    Audit Log
                  │
                  ▼
      XOR Encrypted File Database
```

---

# 📂 Project Structure

```text
SmartBank-Secure-Banking-System/

│
├── Smart_Bank_Final_Code.cpp
├── README.md
├── SmartBank_Project_Report.pdf
├── SmartBank_Proposal.pdf
├── SmartBank_Final_Presentation.pptx
│
├── admin_config.dat
├── db_accounts.dat
├── db_cards.dat
├── db_users.dat
├── db_applications.dat
├── transaction_history.txt
├── audit_log.txt
│
├── Untitled1.exe
└── Untitled1.o
```

---

# 🛠 Technology Stack

| Category | Technology |
|----------|------------|
| Language | C++11 |
| Programming Paradigm | Object-Oriented Programming |
| Security | SHA-256 + Salt + XOR |
| Authentication | Password + OTP |
| Storage | File Handling |
| Encryption | XOR |
| Compiler | GCC / Clang / MSVC |
| Platform | Windows / Linux |

---

# ⚙ Installation

## Clone Repository

```bash
git clone https://github.com/tarikul-cyber30/SmartBank-Secure-Banking-System.git
```

## Compile

```bash
g++ -std=c++11 -Wall -Wextra Smart_Bank_Final_Code.cpp -o SmartBank
```

## Run

### Windows

```bash
SmartBank.exe
```

### Linux

```bash
./SmartBank
```

---

# 🚀 How to Use

1. Compile the project.
2. Launch SmartBank.
3. Select one of the available modules.
4. Register or log in to an account.
5. Perform secure banking operations.
6. Use the Admin Panel for administrative tasks.

---

# 💾 Data Persistence

The application stores all information using persistent flat files.

| File | Purpose |
|------|---------|
| admin_config.dat | Administrator configuration |
| db_accounts.dat | Account database |
| db_cards.dat | ATM card database |
| db_users.dat | User database |
| db_applications.dat | Pending account applications |
| transaction_history.txt | Transaction records |
| audit_log.txt | Security audit log |

---

# 🧪 Testing

The project was tested using:

- SHA-256 Validation
- Salted Password Verification
- OTP Authentication
- Account Lock Testing
- ATM Card Blocking
- Administrator Authentication
- File Encryption Validation
- Data Persistence Testing
- Transaction Processing
- End-to-End Functional Testing

---

# 📸 Screenshots

Add screenshots of the following modules:

- Main Menu
- ATM Module
- Online Banking
- OTP Verification
- Admin Panel
- Transaction History

---

# 🚀 Future Enhancements

- AES-256 Database Encryption
- SQLite / MySQL Support
- Real SMS & Email OTP
- QR Code Authentication
- Fingerprint Authentication
- GUI Version (Qt)
- REST API Integration
- Cloud Database
- Online Banking Server
- Mobile Banking Application

---

# 👨‍💻 Authors

### Md. Tarikul Islam

Department of Cyber Security Engineering

University of Frontier Technology, Bangladesh

### Akiqur Rahman

Department of Cyber Security Engineering

University of Frontier Technology, Bangladesh

---

# 🎓 Academic Information

**Course:** Object-Oriented Programming Language Sessional

**Course Code:** PROG 112

**Department:** Cyber Security Engineering

**University:** University of Frontier Technology, Bangladesh


## 👨‍🏫 Project Supervisor

**Md. Masud Rana**

Lecturer

Department of Cyber Security Engineering

University of Frontier Technology, Bangladesh

---

# 📄 License

This project was developed for academic and educational purposes as part of the **Object-Oriented Programming Language Sessional** course.

The source code may be used for learning and research with proper attribution.

---

# ⭐ Support

If you found this project useful, please consider giving it a ⭐ on GitHub.

Thank you for visiting this repository!
