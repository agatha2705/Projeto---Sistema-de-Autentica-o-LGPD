import bcrypt
import pyotp
import time
import secrets
import re
import json  # NOVO
from email_validator import validate_email, EmailNotValidError
import mysql.connector
from dotenv import load_dotenv
import os

# carregar variáveis do .env
load_dotenv()

# conexão com o MySQL
conn = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    port=3306
)

cursor = conn.cursor()

tentativas = {}
sessoes = {}  # NOVO

# LOG
def log(mensagem):
    print(f"[LOG {time.strftime('%H:%M:%S')}] {mensagem}")

# validação de email
def validar_email(email):
    try:
        email_info = validate_email(email, check_deliverability=False)
        return email_info.normalized
    except EmailNotValidError as e:
        print(f"Email inválido: {str(e)}")
        return None

# validação de senha
def validar_senha(senha):
    erros = []

    if len(senha) < 8:
        erros.append("mínimo 8 caracteres")

    if not re.search(r'[A-Z]', senha):
        erros.append("uma letra maiúscula")

    if not re.search(r'\d', senha):
        erros.append("um número")

    if not re.search(r'[!@#$%&*]', senha):
        erros.append("um caractere especial (!@#$%&*)")

    if erros:
        print("Senha inválida! Faltando:")
        for erro in erros:
            print(f" - {erro}")
        return False

    return True

# NOVO - backup codes
def gerar_backup_codes():
    return [secrets.token_hex(4) for _ in range(5)]

# cadastro
def cadastrar():
    print("\n--- CADASTRO ---")

    while True:
        email_input = input("Digite seu email: ")
        email_validado = validar_email(email_input)

        if not email_validado:
            continue

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email_validado,))
        if cursor.fetchone():
            print("Este email já está cadastrado!")
        else:
            email = email_validado
            break

    while True:
        print("Cadastre aqui sua senha com os seguintes critérios: \n"
                "        *Ao menos 8 digitos\n"
                "        *Ao menos uma letra MAIÚSCULA\n"
                "        *Ao menos um número\n"
                "        *Ao menos um caractere especial(!@#$%¨&*)\n")
        
        senha = input("Digite sua senha: ")

        if not validar_senha(senha):
            continue

        confirmar_senha = input("Confirme sua senha: ")

        if senha != confirmar_senha:
            print("Senhas não conferem")
        else:
            break

    senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())

    chave_2fa = pyotp.random_base32()

    backup_codes = gerar_backup_codes()  # NOVO

    cursor.execute("""
        INSERT INTO usuarios (email, senha_hash, chave_2fa, bloqueado_ate, backup_codes)
        VALUES (%s, %s, %s, %s, %s)
    """, (email, senha_hash, chave_2fa, 0, json.dumps(backup_codes)))

    conn.commit()

    print("\nCadastro realizado com sucesso!")
    print("Chave 2FA:", chave_2fa)

    print("\nCódigos de recuperação:")  # NOVO
    for code in backup_codes:
        print(code)

    log(f"Usuário {email} cadastrado")

# login
def login():
    print("\n--- LOGIN ---")

    while True:
        email_input = input("Email: ")
        email_validado = validar_email(email_input)

        if not email_validado:
            continue

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email_validado,))
        usuario = cursor.fetchone()

        if not usuario:
            print("Usuário não encontrado")
        else:
            email = email_validado
            break

    senha_hash = usuario[1]
    chave_2fa = usuario[2]
    bloqueado_ate = usuario[3]
    backup_codes = json.loads(usuario[4])  # NOVO

    if time.time() < bloqueado_ate:
        print("Conta bloqueada temporariamente")
        return

    while True:
        senha = input("Senha: ")

        if bcrypt.checkpw(senha.encode(), senha_hash):
            print("Senha correta!")
            log(f"Login correto: {email}")
            tentativas[email] = 0
            verificar_2fa(email, chave_2fa, backup_codes)  # ALTERADO
            break
        else:
            print("Senha incorreta!")
            log(f"Erro de senha: {email}")

            tentativas[email] = tentativas.get(email, 0) + 1

            time.sleep(2)

            if tentativas[email] >= 5:
                cursor.execute("""
                    UPDATE usuarios SET bloqueado_ate = %s WHERE email = %s
                """, (time.time() + 600, email))
                conn.commit()

                print("Conta bloqueada por 10 minutos!")
                return

# 2FA
def verificar_2fa(email, chave_2fa, backup_codes):  # ALTERADO
    totp = pyotp.TOTP(chave_2fa)

    while True:
        codigo = input("Digite o código do app ou backup: ")

        # backup code
        if codigo in backup_codes:
            print("Login com código de recuperação!")
            backup_codes.remove(codigo)

            cursor.execute("""
                UPDATE usuarios SET backup_codes = %s WHERE email = %s
            """, (json.dumps(backup_codes), email))
            conn.commit()

            criar_sessao(email)  # NOVO
            return

        if totp.verify(codigo, valid_window=1):
            print("2FA válido! Acesso liberado")
            log(f"2FA validado: {email}")

            criar_sessao(email)  # NOVO
            return
        else:
            print("Código inválido")

# NOVO - sessão
def criar_sessao(email):
    token = secrets.token_hex(16)

    sessoes[token] = {
        "email": email,
        "expira": time.time() + 900
    }

    print("Token da sessão:", token)

# NOVO - validar sessão
def validar_sessao(token):
    if token not in sessoes:
        return False

    if time.time() > sessoes[token]["expira"]:
        del sessoes[token]
        print("Sessão expirada")
        return False

    return True

# NOVO - logout
def logout(token):
    if token in sessoes:
        del sessoes[token]
        print("Logout realizado")

# NOVO - esqueci a senha
def esqueci_senha():
    print("\n--- RECUPERAÇÃO DE SENHA ---")

    email = input("Digite seu email: ")

    cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        print("Usuário não encontrado")
        return

    token = secrets.token_hex(4)
    print("Token de recuperação (simulação):", token)

    token_digitado = input("Digite o token recebido: ")

    if token_digitado != token:
        print("Token inválido")
        return

    while True:
        nova_senha = input("Digite a nova senha: ")

        if not validar_senha(nova_senha):
            continue

        confirmar = input("Confirme a nova senha: ")

        if nova_senha != confirmar:
            print("Senhas não conferem")
        else:
            break

    senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt())

    cursor.execute("""
        UPDATE usuarios SET senha_hash = %s WHERE email = %s
    """, (senha_hash, email))

    conn.commit()

    print("Senha redefinida com sucesso!")
    log(f"Senha redefinida: {email}")

# menu
def menu():
    while True:
        print("\n--- MENU ---")
        print("1 - Cadastrar")
        print("2 - Login")
        print("3 - Esqueci minha senha")  # NOVO

        opcao = input("Escolha: ")

        if opcao == "1":
            cadastrar()

        elif opcao == "2":
            login()

        elif opcao == "3":  # NOVO
            esqueci_senha()

        else:
            print("Opção inválida")

menu()