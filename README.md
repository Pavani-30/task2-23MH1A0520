# task2-23MH1A0520
# PKI-Based 2FA Microservice (TOTP)

This project implements a **PKI-based Two-Factor Authentication (2FA) microservice** using **RSA encryption**, **TOTP (Time-based One-Time Passwords)**, **FastAPI**, **Docker**, **Docker Compose**, and **Cron jobs**.

It is developed as part of **Global Placement Programme – Task 2**.

---

##  Features

- RSA (PKI) based encrypted seed decryption
- Secure TOTP generation (RFC 6238 compatible)
- TOTP verification with time-window tolerance
- REST APIs built using FastAPI
- Cron job that logs 2FA codes every minute
- Dockerized application with persistent volumes
- Docker Compose for easy local testing

---

##  Tech Stack

- **Python 3.11**
- **FastAPI**
- **pyotp**
- **cryptography**
- **Uvicorn**
- **Docker & Docker Compose**
- **Linux cron**

---

##  Project Structure

