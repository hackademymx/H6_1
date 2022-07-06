from django.core.mail import EmailMessage, send_mail
import random
import string


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.send()


    def new_password():

        length = 10
        pwd = ''
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        num = string.digits
        symbols = string.punctuation

        all = lower + upper + num + symbols
        temp = random.sample(all, length)
        pwd = "".join(temp)

        return pwd

    # print(new_password())

