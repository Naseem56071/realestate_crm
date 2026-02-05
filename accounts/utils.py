import requests
import random
import json
from django.conf import settings


def send_sms(phone, otp):
    url = "https://smslogin.co/v3/api.php"

    payload = {
        "username": settings.SMS_USERNAME,
        "apikey": settings.SMS_API_KEY,
        "senderid": settings.SMS_SENDER_ID,
        "mobile": "91" + phone,
        "message": f"Thank you for registering with Sunseaz Technologies. Your one-time password is {otp} for registering with us.",
        "templateid": settings.SMS_TEMPLATE_ID
    }

    try:
        response = requests.get(url, params=payload, timeout=10)
        text = response.text.strip()

        print("SMS RAW RESPONSE:", text)

        # smslogin returns JSON-like string with campid

        if response.status_code == 200 and "campid" in text:
            return True, text
        else:
            return False, text

    except requests.exceptions.RequestException as e:
        return False, str(e)


def generate_otp():
    return str(random.randint(100000, 999999))





