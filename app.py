import secrets

from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# User database (simplified)
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

# Document database
documents = {
    1: {
        "id": 1,
        "title": "Alice's Private Document",
        "content": "Secret content for Alice",
        "owner_id": 1,
    },
    2: {
        "id": 2,
        "title": "Bob's Private Document",
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


@app.post("/login")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    for user in users.values():
        if user["username"] == username and user["password"] == password:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return jsonify(
                {
                    "message": "Login successful",
                    "user_id": user["id"],
                    "role": user["role"],
                }
            )

    return jsonify({"error": "Invalid credentials"}), 401


@app.get("/user/<int:user_id>")
def get_user(user_id):
    # Vulnerability 1: No authentication check
    # Vulnerability 2: Access to other users' information (IDOR)
    if user_id in users:
        user = users[user_id].copy()
        user.pop("password")  # Exclude password
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404


@app.get("/document/<int:doc_id>")
def get_document(doc_id):
    # Vulnerability 3: No owner check (IDOR)
    if doc_id in documents:
        return jsonify(documents[doc_id])
    return jsonify({"error": "Document not found"}), 404


@app.post("/user/<int:user_id>/role")
def update_role(user_id):
    # Vulnerability 4: No admin permission check (privilege escalation)
    data = request.get_json()
    new_role = data.get("role")

    if user_id in users:
        users[user_id]["role"] = new_role
        return jsonify({"message": f"Role updated to {new_role}"})
    return jsonify({"error": "User not found"}), 404


@app.get("/admin/users")
def admin_users():
    # Vulnerability 5: Insufficient admin permission check
    if session.get("role") == "admin":
        return jsonify(list(users.values()))
    return jsonify({"error": "Admin access required"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)