import secrets
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# User database (INSECURE)
users = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "password123",
        "role": "user",
        "email": "alice@example.com",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "password456",
        "role": "user",
        "email": "bob@example.com",
    },
    3: {
        "id": 3,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
    },
}

# Document database (INSECURE)
documents = {
    1: {
        "id": 1,
        "title": "Alice Private Document",
        "content": "Secret content for Alice",
        "owner_id": 1,
    },
    2: {
        "id": 2,
        "title": "Bob Private Document",
        "content": "Secret content for Bob",
        "owner_id": 2,
    },
    3: {
        "id": 3,
        "title": "Admin Document",
        "content": "Admin only content",
        "owner_id": 3,
    },
}


# ---------------------------------------------------
# AUTHENTICATION (WEAK)
# ---------------------------------------------------
@app.post("/login")
def login():
    data = request.get_json()

    # Broken Access Control:
    # Trusting client input without validation
    for user in users.values():
        if (
            user["username"] == data.get("username")
            and user["password"] == data.get("password")
        ):
            # Session fixation / excessive trust
            session["user_id"] = user["id"]
            session["role"] = data.get("role", user["role"])  # CLIENT-CONTROLLED ROLE
            return jsonify({"message": "Login successful"})

    return jsonify({"error": "Invalid credentials"}), 401


# ---------------------------------------------------
# USER DATA (IDOR + NO AUTH CHECK)
# ---------------------------------------------------
@app.get("/user/<int:user_id>")
def get_user(user_id):
    # A01: No authentication
    # A01: IDOR – any user can read any other user
    if user_id in users:
        return jsonify(users[user_id])  # password exposed intentionally
    return jsonify({"error": "User not found"}), 404


# ---------------------------------------------------
# DOCUMENT ACCESS (IDOR)
# ---------------------------------------------------
@app.get("/document/<int:doc_id>")
def get_document(doc_id):
    # A01: No authentication
    # A01: No ownership validation
    if doc_id in documents:
        return jsonify(documents[doc_id])
    return jsonify({"error": "Document not found"}), 404


# ---------------------------------------------------
# ROLE MODIFICATION (PRIVILEGE ESCALATION)
# ---------------------------------------------------
@app.post("/user/<int:user_id>/role")
def update_role(user_id):
    # A01: No authentication
    # A01: No authorization
    # A01: Horizontal + Vertical privilege escalation
    data = request.get_json()

    if user_id in users:
        users[user_id]["role"] = data.get("role")
        return jsonify({"message": "Role updated"})
    return jsonify({"error": "User not found"}), 404


# ---------------------------------------------------
# ADMIN FUNCTIONALITY (BROKEN CHECK)
# ---------------------------------------------------
@app.get("/admin/users")
def admin_users():
    # A01: Authorization based only on client-controlled session value
    if session.get("role"):
        return jsonify(list(users.values()))  # exposes all users
    return jsonify({"error": "Access denied"}), 403


# ---------------------------------------------------
# MASS ASSIGNMENT (BROKEN ACCESS CONTROL)
# ---------------------------------------------------
@app.put("/user/<int:user_id>")
def update_user(user_id):
    # A01: Mass assignment
    # A01: No authentication
    data = request.get_json()

    if user_id in users:
        users[user_id].update(data)  # allows role, id, password overwrite
        return jsonify(users[user_id])
    return jsonify({"error": "User not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
