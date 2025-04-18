
import streamlit as st
import sqlite3
import bcrypt
import random
import smtplib
from email.message import EmailMessage
from config import EMAIL_ADDRESS, EMAIL_PASSWORD

st.set_page_config(page_title="Employee Login System", layout="centered")

# ========== DATABASE SETUP ==========
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

# ========== PASSWORD UTILS ==========
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# ========== USER DB OPERATIONS ==========
def register_user(name, email, password, role):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                  (name, email, hash_password(password), role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_user(email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT name, password, role FROM users WHERE email = ?", (email,))
    data = c.fetchone()
    conn.close()
    if data:
        name, hashed, role = data
        if verify_password(password, hashed):
            return name, role
    return None, None

def update_password(email, new_password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE email = ?", (hash_password(new_password), email))
    conn.commit()
    conn.close()

def email_exists(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()
    return result is not None

# ========== EMAIL OTP ==========
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(receiver_email, otp):
    msg = EmailMessage()
    msg['Subject'] = 'Your OTP for Password Reset'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your OTP to reset password is: {otp}\nDo not share it with anyone.')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ========== MAIN APP ==========
def main():
    init_db()
    st.title("🔐 Employee Login System")

    menu = ["Login", "Register", "Forgot Password"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Create a New Account")
        name = st.text_input("Full Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type='password')
        role = st.selectbox("Role", ["Employee", "Manager", "Admin"])

        if st.button("Register"):
            if name and email and password:
                if register_user(name, email, password, role):
                    st.success("🎉 Registered successfully! You can now log in.")
                else:
                    st.error("🚫 Email already registered.")
            else:
                st.warning("Please fill all fields.")

    elif choice == "Login":
        st.subheader("Login to your Account")
        email = st.text_input("Email")
        password = st.text_input("Password", type='password')

        if st.button("Login"):
            name, role = login_user(email, password)
            if name:
                st.success(f"✅ Welcome {name} ({role})")
                st.info("You are now logged in.")
                if role == "Admin":
                    st.write("🔧 Admin Dashboard (coming soon...)")
                elif role == "Manager":
                    st.write("📋 Manager Dashboard (coming soon...)")
                else:
                    st.write("🧑‍💼 Employee Dashboard (coming soon...)")
            else:
                st.error("❌ Invalid email or password.")

    elif choice == "Forgot Password":
        st.subheader("🔑 Forgot Password")
        email = st.text_input("Enter your registered email")
        if st.button("Send OTP"):
            if email_exists(email):
                otp = generate_otp()
                st.session_state['otp'] = otp
                st.session_state['reset_email'] = email
                send_otp(email, otp)
                st.success("📨 OTP sent to your email.")
            else:
                st.error("❌ Email not registered.")

        if 'otp' in st.session_state:
            entered_otp = st.text_input("Enter OTP")
            new_pass = st.text_input("Enter New Password", type='password')

            if st.button("Reset Password"):
                if entered_otp == st.session_state['otp']:
                    update_password(st.session_state['reset_email'], new_pass)
                    st.success("✅ Password reset successful. Please login.")
                    del st.session_state['otp']
                    del st.session_state['reset_email']
if __name__ == '__main__':
    main()
