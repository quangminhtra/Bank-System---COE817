# Secure Banking System (COE817 Project)

## Overview
This project implements a secure client-server banking system using Java.  
It is based on concepts from **Lab 3 (authentication & key exchange)** and **Lab 4 (secure messaging & integrity protection)**.

Features of the project - in the manual
- Secure registration using RSA
- Password-based authentication using PBKDF2
- Mutual authentication with nonce challenge-response
- Session key derivation (encryption + MAC keys)
- Secure transactions (AES + HMAC)
- Replay protection (sequence numbers)
- Encrypted audit logging
- Multi-client support (ATM clients)

---

## How to Run onNetBeans 16

### Step 1 — Open Project
1. Open NetBeans
2. Click: File --> Open Project --> the project of banksystem

### Step 2 — Run Project
1. Right-click project → **Run** --> Set the main class is UI_Bank.DemoLaunchaer.java 
2. The following will open:
- Server window
- 3 ATM client windows

---

## How to Use the System

### 1. Start Server
- Click **Start Server** on server window

---

### 2. Register a User
On any ATM:
- Click **Connect**
- Enter: user - test1, pass123 - you can do another one if wanted but register first then login - check the server log as well if it said register successfully or not

- Click **Register**

Expected: REGISTER - OK


### 3. Login
- Enter same credentials
- Click **Login**

Expected: Authenticated - Session established


---

### 4. Perform Transactions
Try:
- Deposit → 100
- Withdraw → 50
- Balance → shows updated amount

---

## Data Storage 

### User Data File
your information is in users.db but the pass is hash already

test1|salt|120000|derivedKey|50 
- `test1` → username
- `salt` → random salt (Base64)
- `120000` → PBKDF2 iterations
- `derivedKey` → hashed password (NOT plaintext)
- `50` → current balance

## Audit Log

### File:
audit.log.enc

- Stored in encrypted form
- Cannot be read directly

### To view:
- Click: in server UI

---

