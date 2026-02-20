import requests
import random
import json
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


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


def lead_email_send(task):
    dashboard_url = settings.SITE_URL + "/agent/dashboard/"
    if not task.agent or not task.agent.email:
        return False  # no agent email → do nothing

    agent_email = task.agent.email

    context = {
        "agent_name": task.agent.name,
        "lead_name": task.name,
        "lead_email": task.email,
        "lead_phone": task.phone,
        "lead_message": task.description,
        "dashboard_url": dashboard_url,
    }

    # Plain text version
    text_content = render_to_string("accounts/emails/lead_assigned.txt", context)

    # HTML version
    html_content = render_to_string("accounts/emails/lead_assigned.html", context)

    msg = EmailMultiAlternatives(
        subject="New Lead Assigned To You",
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,   # uses DEFAULT_FROM_EMAIL
        to=[agent_email],
    )
   
    msg.attach_alternative(html_content, "text/html")
    msg.send()
    return True
  