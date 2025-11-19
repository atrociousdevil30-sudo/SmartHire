# SmartHire - Login Credentials

## Problem Solved ✅

The login issue was caused by **mismatched passwords in the database**. All user passwords have been reset to a working state.

---

## Current Login Credentials

All users now have the password: **`password123`**

### Employee Accounts:
1. **Username:** Deeksha Shetti  
   **Password:** password123  
   **Role:** Employee

2. **Username:** Pavan M  
   **Password:** password123  
   **Role:** Employee

3. **Username:** Deepthi  
   **Password:** password123  
   **Role:** Employee

### HR Accounts:
1. **Username:** Deeksha N.S  
   **Password:** password123  
   **Role:** HR

### Manager Accounts:
1. **Username:** manager1  
   **Password:** password123  
   **Role:** Manager

2. **Username:** manager2  
   **Password:** password123  
   **Role:** Manager

---

## How to Change Your Password

Once logged in:
1. Go to **Employee Portal** (if you're an employee)
2. Click on your profile in the navbar dropdown
3. Click the **Change Password** button
4. Enter your current password and new password
5. Click **Save** to update

---

## Troubleshooting

### Still can't login?
1. Make sure you're using the **exact username** (case-sensitive for the form, but accepts lowercase)
2. Ensure caps lock is **OFF** for the password
3. Try a different browser or clear cookies
4. Check that you're selecting the correct role (Employee or HR)

### Password still not working?
Contact your administrator to reset your password again.

---

## Technical Details

- **Password hashing:** Werkzeug security (scrypt)
- **Session management:** Flask session with optional "Remember Me"
- **Role-based access:** HR and Employee dashboards are separate

---

**Last Updated:** November 19, 2025
