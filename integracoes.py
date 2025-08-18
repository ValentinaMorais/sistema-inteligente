import requests

# Coloque aqui o token do seu bot (gerado pelo BotFather no Telegram)
TELEGRAM_TOKEN = "SEU_TOKEN_AQUI"
CHAT_ID = "SEU_CHAT_ID_AQUI"  # ID do grupo ou usuário que receberá as mensagens

BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}"

def enviar_mensagem(mensagem: str):
    """
    Envia uma mensagem para o chat configurado no Telegram.
    """
    try:
        url = f"{BASE_URL}/sendMessage"
        payload = {"chat_id": CHAT_ID, "text": mensagem}
        requests.post(url, data=payload)
    except Exception as e:
        print("Erro ao enviar mensagem para o Telegram:", e)
