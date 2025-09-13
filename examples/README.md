# Quart-Auth Extended Examples

This directory contains examples demonstrating the extended features of Quart-Auth.

## Examples

### `extended_auth_demo.py`

Complete demonstration of storing additional user data securely in authentication cookies.

**Features shown:**
- Creating users with custom data (`create_user_with_data`)
- Storing complex data structures (preferences, metadata, etc.)
- Accessing user data via `current_user.get()`
- Role-based access control using stored data
- orjson optimization (when available)

**Run the demo:**
```bash
python examples/extended_auth_demo.py
```

Then visit http://localhost:5000 and try:
- `/login/admin` - Login as admin with full permissions
- `/login/john` - Login as regular user
- `/profile` - View all stored user data
- `/admin-only` - Admin-only endpoint using role data
- `/logout` - Logout

## Key Features Demonstrated

### 1. Secure Data Storage
All user data is stored in cryptographically signed cookies - users cannot read or modify the data.

### 2. Complex Data Structures
Store nested objects, arrays, and any JSON-serializable data:
```python
user = create_user_with_data(
    auth_id="user_123",
    username="john",
    preferences={"theme": "dark"},
    metadata={"departments": ["IT", "Security"]}
)
```

### 3. Easy Data Access
```python
@login_required
async def some_route():
    username = current_user.get("username")
    role = current_user.get("role")
    all_data = current_user.user_data
```

### 4. Performance Optimization
Uses orjson automatically if installed for better JSON serialization performance.

## Installation

```bash
pip install git+https://github.com/pastanetwork/quart-auth.git
pip install orjson  # Optional, for better performance
```