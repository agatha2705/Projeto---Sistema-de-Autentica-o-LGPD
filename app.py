from flask import Flask, render_template, request, redirect, session
from datetime import timedelta
import time
import bcrypt
import pyotp
import qrcode
import io
import base64
import mysql.connector
from dotenv import load_dotenv
import os
import json
import secrets
import re
from email_validator import validate_email, EmailNotValidError

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

# Sessões com tempo de expiração
app.permanent_session_lifetime = timedelta(minutes=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# BANCO DE DADOS
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=3306
    )

# VALIDAÇÕES
def validar_email(email):
    if not email:
        return None

    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return None

        return email

    except EmailNotValidError:
        return None


def validar_senha(senha):
    if not senha:
        return "Senha obrigatória"

    if len(senha) < 8:
        return "Senha deve ter no mínimo 8 caracteres"

    if not re.search(r"[A-Z]", senha):
        return "Senha precisa de letra maiúscula"

    if not re.search(r"\d", senha):
        return "Senha precisa de número"

    if not re.search(r"[!@#$%&*]", senha):
        return "Senha precisa de caractere especial"

    return None


# LOGIN
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))
        senha = request.form.get("senha") or ""

        if not email:
            return render_template("login.html", erro="Email inválido")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()

        # usuário não existe (não revelar muito detalhe)
        if not usuario:
            conn.close()
            return render_template("login.html", erro="Usuário ou senha inválidos")

        # BLOQUEIO PELO BANCO (FONTE ÚNICA DA VERDADE)
        bloqueado_ate = usuario[3]

        if bloqueado_ate and bloqueado_ate > time.time():
            conn.close()
            return render_template(
                "login.html",
                erro="Conta bloqueada temporariamente. Tente novamente mais tarde."
            )

        # senha errada
        if not bcrypt.checkpw(senha.encode(), usuario[1]):
            # incrementa tentativa no banco usando tempo simples (sem memória)
            tentativas = usuario[6] or 0  # ajuste índice se necessário
            tentativas += 1

            # se chegou no limite
            if tentativas >= 5:
                bloqueio = time.time() + 300  # 5 minutos

                cursor.execute("""
                    UPDATE usuarios
                    SET bloqueado_ate = %s,
                        tentativas = 0
                    WHERE email = %s
                """, (bloqueio, email))

            else:
                cursor.execute("""
                    UPDATE usuarios
                    SET tentativas = %s
                    WHERE email = %s
                """, (tentativas, email))

            conn.commit()
            conn.close()

            return render_template("login.html", erro="Usuário ou senha inválidos")

        # LOGIN OK - limpa bloqueio
        cursor.execute("""
            UPDATE usuarios
            SET tentativas = 0,
                bloqueado_ate = 0
            WHERE email = %s
        """, (email,))
        conn.commit()
        conn.close()

        session["email_temp"] = email

        # fluxo 2FA
        if usuario[5] == 0:
            return redirect("/qr")
        else:
            return redirect("/2fa")

    sucesso = session.pop("sucesso", None)
    return render_template("login.html", sucesso=sucesso)

# CADASTRO
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":

        email = validar_email(request.form.get("email"))
        senha = request.form.get("senha")
        confirmar = request.form.get("confirmar")

        # EMAIL
        if not email:
            return render_template(
                "cadastro.html",
                erro="Email inválido",
                email=request.form.get("email"),
                senha=senha,
                confirmar=confirmar
            )

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return render_template(
                "cadastro.html",
                erro="Email já cadastrado",
                email=email,
                senha=senha,
                confirmar=confirmar
            )

        # SENHA
        erro_senha = validar_senha(senha)
        if erro_senha:
            conn.close()
            return render_template(
                "cadastro.html",
                erro=erro_senha,
                email=email,
                senha=senha,
                confirmar=confirmar
            )

        # CONFIRMAÇÃO
        if senha != confirmar:
            conn.close()
            return render_template(
                "cadastro.html",
                erro="Senhas não conferem",
                email=email,
                senha=senha,
                confirmar=confirmar
            )

        # SALVAR
        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
        chave_2fa = pyotp.random_base32()
        backup_codes = [secrets.token_hex(4) for _ in range(5)]

        cursor.execute("""
            INSERT INTO usuarios (email, senha_hash, chave_2fa, bloqueado_ate, backup_codes)
            VALUES (%s, %s, %s, %s, %s)
        """, (email, senha_hash, chave_2fa, 0, json.dumps(backup_codes)))

        conn.commit()
        conn.close()

        session["sucesso"] = "Cadastro realizado com sucesso!"
        return redirect("/")

    return render_template("cadastro.html")


# 2FA
@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    email = session.get("email_temp")
    if not email:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT chave_2fa, backup_codes FROM usuarios WHERE email = %s", (email,))
    resultado = cursor.fetchone()

    conn.close()

    if not resultado:
        return redirect("/")

    chave_2fa = resultado[0]
    backup_codes = json.loads(resultado[1])

    totp = pyotp.TOTP(chave_2fa)

    if request.method == "POST":
        codigo = request.form["codigo"]

        # BACKUP CODE
        if codigo in backup_codes:
            backup_codes.remove(codigo)

            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE usuarios SET backup_codes = %s WHERE email = %s
            """, (json.dumps(backup_codes), email))

            conn.commit()
            conn.close()

            session["user"] = email
            return redirect("/dashboard")

        # TOTP (Google Authenticator)
        if totp.verify(codigo):
            session["user"] = email
            return redirect("/dashboard")

        return render_template("2fa.html", erro="Código inválido")

    return render_template("2fa.html")

# QR CODE
@app.route("/qr")
def qr():
    if "email_temp" not in session:
        return redirect("/")

    email = session["email_temp"]

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT chave_2fa FROM usuarios WHERE email = %s", (email,))
    resultado = cursor.fetchone()
    conn.close()

    if not resultado:
        return redirect("/")

    chave = resultado[0]

    totp = pyotp.TOTP(chave)

    uri = totp.provisioning_uri(
        name=email,
        issuer_name="Sistema de Autenticacao"
    )

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    img_base64 = base64.b64encode(buffer.read()).decode()

    return render_template("qr.html", qr_code=img_base64)

# QR CODE - confimar se já cadastrou no authenticator
@app.route("/qr-confirm", methods=["POST"])
def qr_confirm():
    email = session.get("email_temp")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE usuarios
        SET twofa_ativo = TRUE
        WHERE email = %s
    """, (email,))

    conn.commit()
    conn.close()

    return redirect("/2fa")

# DASHBOARD
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    return render_template("dashboard.html", email=session["user"])


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()

    response = redirect("/")

    # Evita cache de páginas protegidas
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

# RECUPERAÇÃO DE SENHA (Ainda necessidade de ajustes - Próxima Etapa)
@app.route("/recuperacao", methods=["GET", "POST"])
def recuperacao():
    if request.method == "POST":
        email = validar_email(request.form.get("email"))

        if not email:
            return render_template("recuperacao.html", erro="Email inválido")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cursor.fetchone()
        conn.close()

        if not usuario:
            return render_template("recuperacao.html", erro="Usuário não encontrado")

        token = secrets.token_hex(4)
        session["reset_token"] = token
        session["reset_email"] = email

        print("TOKEN (simulação):", token)

        return redirect("/resetar")

    return render_template("recuperacao.html")


# RESETAR SENHA (Ainda necessidade de ajustes - Próxima Etapa)
@app.route("/resetar", methods=["GET", "POST"])
def resetar():
    if request.method == "POST":
        token = request.form["token"]
        nova_senha = request.form["senha"]

        if token != session.get("reset_token"):
            return render_template("resetar.html", erro="Token inválido")

        erro_senha = validar_senha(nova_senha)
        if erro_senha:
            return render_template("resetar.html", erro=erro_senha)

        email = session.get("reset_email")

        senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt())

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE usuarios SET senha_hash = %s WHERE email = %s
        """, (senha_hash, email))

        conn.commit()
        conn.close()

        session.pop("reset_token", None)
        session.pop("reset_email", None)

        return render_template("login.html", sucesso="Senha redefinida com sucesso!")

    return render_template("resetar.html")


# RODAR APP
if __name__ == "__main__":
    app.run(debug=True)