import smtplib
from email.mime.multipart import MIMEMultipart

def send_smtp_message(mime_message: MIMEMultipart, smtp_user: str, smtp_password: str):
    """
    Envía un mensaje MIME a través del servidor SMTP de Office 365 (Outlook).
    """
    # a) Conectarse a smtp.office365.com en el puerto 587
    server = smtplib.SMTP("smtp.office365.com", 587)
    try:
        # b) Ejecutar .starttls() para asegurar la conexión cifrada
        server.starttls()
        
        # c) Iniciar sesión con las credenciales provistas
        server.login(smtp_user, smtp_password)
        
        # d) Enviar el correo y cerrar la conexión de manera segura
        server.send_message(mime_message)
    finally:
        server.quit()
