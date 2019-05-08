from email.mime.text import MIMEText
import subprocess


def my_sendmail(fr: str, to: str, subj: str, body: str) -> tuple:
    msg = MIMEText(body, 'plain', 'utf-8')
    msg["From"] = fr
    msg["To"] = to
    msg["Subject"] = subj
    p = subprocess.Popen(["/usr/sbin/sendmail", "-t"], stdin=subprocess.PIPE)
    return p.communicate(msg.as_string())
