import secrets
from flask import Flask, jsonify, request, session

# BAD: nombre de variable no descriptivo
aPP = Flask(__name__)
aPP.secret_key = secrets.token_hex(16)

# BAD: constantes en minúsculas, nombres genéricos
usrDB = {
    1: {
        "Id": 1,                     # BAD: CamelCase inconsistente
        "UserName": "alice",         # BAD: PascalCase
        "PASSWORD": "password123",   # BAD: mayúsculas innecesarias
        "rol": "user",               # BAD: idioma inconsistente
        "emailAddress": "alice@example.com",
    },
    2: {
        "Id": 2,
        "UserName": "bob",
        "PASSWORD": "password456",
        "rol": "user",
        "emailAddress": "bob@example.com",
    },
    3: {
        "Id": 3,
        "UserName": "admin",
        "PASSWORD": "admin123",
        "rol": "admin",
        "emailAddress": "admin@example.com",
    },
}

# BAD: nombre poco claro y mezcla de estilos
Doc_DB = {
    1: {
        "ID": 1,
        "Title": "Alice Private Document",
        "CONTENT": "Secret content for Alice",
        "OwnerId": 1,
    },
    2: {
        "ID": 2,
        "Title": "Bob Private Document",
        "CONTENT": "Secret content for Bob",
        "OwnerId": 2,
    },
    3: {
        "ID": 3,
        "Title": "Admin Document",
        "CONTENT": "Admin only content",
        "OwnerId": 3,
    },
}


# ---------------------------------------------------
# AUTH (BAD NAMING + BROKEN ACCESS CONTROL)
# ---------------------------------------------------
@aPP.post("/login")
def LOGIN():  # BAD: función en mayúsculas
    d = request.get_json()  # BAD: variable sin significado

    for x in usrDB.values():  # BAD: variable genérica
        if (
            x["UserName"] == d.get("username")
            and x["PASSWORD"] == d.get("password")
        ):
            # BAD: claves de sesión inconsistentes
            session["UID"] = x["Id"]
            session["USER_ROLE"] = d.get("role", x["rol"])
            return jsonify({"msg": "ok"})  # BAD: mensaje poco claro

    return jsonify({"ERR": "no"}), 401


# ---------------------------------------------------
# USER DATA (IDOR + BAD CONVENTIONS)
# ---------------------------------------------------
@aPP.get("/user/<int:ID>")
def getUsr(ID):  # BAD: mezcla camelCase
    if ID in usrDB:
        return jsonify(usrDB[ID])  # expone PASSWORD
    return jsonify({"errorMSG": "User missing"}), 404


# ---------------------------------------------------
# DOCUMENT ACCESS (IDOR)
# ---------------------------------------------------
@aPP.get("/document/<int:docID>")
def DOC(docID):  # BAD: nombre no descriptivo
    if docID in Doc_DB:
        return jsonify(Doc_DB[docID])
    return jsonify({"E": "404"}), 404


# ---------------------------------------------------
# ROLE UPDATE (PRIVILEGE ESCALATION)
# ---------------------------------------------------
@aPP.post("/user/<int:uId>/role")
def rOLE(uId):  # BAD: nombre inconsistente
    dataX = request.get_json()

    if uId in usrDB:
        usrDB[uId]["rol"] = dataX.get("role")
        return jsonify({"STATUS": "changed"})
    return jsonify({"err": "not found"}), 404


# ---------------------------------------------------
# ADMIN ENDPOINT (BROKEN CHECK)
# ---------------------------------------------------
@aPP.get("/admin/users")
def ADMIN_users():  # BAD: snake + camel + uppercase
    if session.get("USER_ROLE"):
        return jsonify(list(usrDB.values()))
    return jsonify({"DENIED": True}), 403


# ---------------------------------------------------
# MASS ASSIGNMENT (VERY BAD PRACTICE)
# ---------------------------------------------------
@aPP.put("/user/<int:id>")
def upd(id):  # BAD: sombreado de built-in
    body = request.get_json()

    if id in usrDB:
        usrDB[id].update(body)  # permite sobrescribir todo
        return jsonify(usrDB[id])
    return jsonify({"x": "no"}), 404


if __name__ == "__main__":
    aPP.run(host="0.0.0.0", port=5000, debug=True)
