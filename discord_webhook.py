import requests

# Webhook URL (получите в настройках Discord канала)
WEBHOOK_URL = "https://discord.com/api/webhooks/1474867611777896530/hzZgvNpkuZaWsAv2MHw0PqYVzCBK9aa39NSjOF7cMFbaV1m8WbIxdYr4z-yzYQ1e7e6f"

def send_message(text):
    """Отправляет сообщение в Discord через webhook"""
    data = {"content": text}
    response = requests.post(WEBHOOK_URL, json=data)
    return response.status_code == 204

if __name__ == "__main__":
    # Пример использования
    message = "Привет! Это тестовое сообщение."
    
    if send_message(message):
        print("Сообщение отправлено!")
    else:
        print("Ошибка отправки")
