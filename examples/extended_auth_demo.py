"""
Example demonstrating the extended authentication features in quart-auth.
This shows how to store and modify user data securely in cookies using current_user
as a mutable dictionary (like session).

Run with: python examples/extended_auth_demo.py
Then visit:
- http://localhost:5000/login/admin - Login as admin with additional data
- http://localhost:5000/login/john - Login as regular user
- http://localhost:5000/profile - View stored user data
- http://localhost:5000/update-profile - Modify user data dynamically
- http://localhost:5000/session-info - View session and expiration info
- http://localhost:5000/logout - Logout
"""

from quart import Quart, ResponseReturnValue

try:
    import orjson
    def jsonify_func(data):
        return orjson.dumps(data).decode('utf-8'), 200, {'Content-Type': 'application/json'}
except ImportError:
    from quart import jsonify
    jsonify_func = jsonify

from quart_auth import (
    QuartAuth,
    login_user,
    current_user,
    login_required,
    logout_user,
    create_user_with_data
)


app = Quart(__name__)
app.secret_key = "your-secret-key-here-change-in-production"

# Initialize quart-auth
auth = QuartAuth(app)


@app.route("/")
async def index() -> ResponseReturnValue:
    return """
    <h1>Quart-Auth Extended Demo</h1>
    <p>Try these endpoints:</p>
    <ul>
        <li><a href="/login/admin">Login as admin</a></li>
        <li><a href="/login/john">Login as john</a></li>
        <li><a href="/profile">View profile (requires login)</a></li>
        <li><a href="/update-profile">Update profile data (requires login)</a></li>
        <li><a href="/session-info">View session information</a></li>
        <li><a href="/logout">Logout</a></li>
    </ul>
    """


@app.route("/login/<username>")
async def login(username: str) -> ResponseReturnValue:
    # Create a user with additional data stored securely in the cookie
    user = create_user_with_data(
        auth_id=f"user_{username}",
        username=username,
        email=f"{username}@example.com",
        role="admin" if username == "admin" else "user",
        preferences={"theme": "dark", "language": "en"},
        metadata={
            "last_login": "2024-01-15",
            "login_count": 42,
            "departments": ["IT", "Security"] if username == "admin" else ["Users"]
        }
    )

    login_user(user, remember=True)
    return f"""
    <h2>Successfully logged in as {username}!</h2>
    <p>User data has been securely stored in your authentication cookie.</p>
    <p><a href="/profile">View your profile</a></p>
    """


@app.route("/profile")
@login_required
async def profile() -> ResponseReturnValue:
    """Display all user data stored in the authentication cookie."""
    return jsonify_func({
        "message": "User profile data retrieved from secure cookie",
        "auth_id": current_user.auth_id,
        "username": current_user.get("username"),
        "email": current_user.get("email"),
        "role": current_user.get("role"),
        "preferences": current_user.get("preferences"),
        "metadata": current_user.get("metadata"),
        "all_user_data": current_user.user_data,
        "is_admin": current_user.get("role") == "admin",
        "session_info": {
            "remember_me": current_user.remember_me,
            "expires_at": current_user.expires_at.isoformat() if current_user.expires_at else None,
            "remaining_days": current_user.remaining.days if current_user.remaining else None,
            "is_permanent": current_user.remember_me
        }
    })


@app.route("/admin-only")
@login_required
async def admin_only() -> ResponseReturnValue:
    """Example of role-based access using stored user data."""
    if current_user.get("role") != "admin":
        return "Access denied: Admin role required", 403

    return jsonify_func({
        "message": "Welcome to the admin area!",
        "user": current_user.get("username"),
        "departments": current_user.get("metadata", {}).get("departments", [])
    })


@app.route("/update-profile")
@login_required
async def update_profile() -> ResponseReturnValue:
    """Demonstrate modifying user data using current_user as a mutable dictionary."""
    # Modify user data directly like session
    current_user['last_visit'] = "2024-03-15"
    current_user['visit_count'] = current_user.get('visit_count', 0) + 1

    # Update preferences
    if 'preferences' not in current_user:
        current_user['preferences'] = {}
    current_user['preferences']['theme'] = 'light' if current_user['preferences'].get('theme') == 'dark' else 'dark'

    # Add new data
    current_user.update({
        'updated_at': '2024-03-15T10:30:00Z',
        'feature_flags': ['new_ui', 'beta_features']
    })

    return jsonify_func({
        "message": "Profile updated successfully! Cookie automatically updated.",
        "updated_data": {
            "last_visit": current_user['last_visit'],
            "visit_count": current_user['visit_count'],
            "preferences": current_user['preferences'],
            "updated_at": current_user['updated_at'],
            "feature_flags": current_user['feature_flags']
        },
        "all_user_data": dict(current_user)
    })


@app.route("/session-info")
@login_required
async def session_info() -> ResponseReturnValue:
    """Display session and expiration information."""
    from datetime import datetime, timedelta

    expires_at = current_user.expires_at
    session_data = {
        "auth_id": current_user.auth_id,
        "remember_me": current_user.remember_me,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "session_type": "Permanent" if current_user.remember_me else "Temporary (browser session)",
    }

    if expires_at:
        remaining = current_user.remaining
        session_data.update({
            "remaining_time": str(remaining),
            "expires_in_days": remaining.days if remaining else 0,
            "expires_in_hours": remaining.total_seconds() // 3600 if remaining else 0,
            "expires_soon": remaining < timedelta(days=7) if remaining else True
        })

    return jsonify_func({
        "message": "Session information",
        "session": session_data,
        "current_time": datetime.now().isoformat(),
        "note": "remember_me and expires_at are read-only system properties"
    })


@app.route("/logout")
@login_required
async def logout() -> ResponseReturnValue:
    logout_user()
    return '<h2>Logged out successfully!</h2><p><a href="/">Back to home</a></p>'


if __name__ == "__main__":
    print("Starting Quart-Auth Extended Demo...")
    print("Visit http://localhost:5000 to try the demo")
    app.run(debug=True)