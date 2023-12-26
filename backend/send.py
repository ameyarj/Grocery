from celery import Celery
from celery.schedules import crontab
from datetime import datetime
from flask_mail import Mail, Message as FlaskMailMessage
from app import *


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'billgatesms57@gmail.com'
app.config['MAIL_PASSWORD'] = 'wiqhopynvfdduwyb'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = "billgatesms57@gmail.com"

mail = Mail(app)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'

celery = Celery('celery', broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)
celery.conf.enable_utc = False
celery.conf.timezone = 'Asia/Kolkata'

@celery.task(name='app.send_daily_reminders')
def send_daily_reminders():
    with app.app_context():
        print("Task started")
        current_time = datetime.utcnow()
        users = User.query.all()
        print(f"Found {len(users)} users")
        recipient_emails = [user.email for user in users]

        if recipient_emails:
            mail = Mail(current_app)
            for email in recipient_emails:
                msg = FlaskMailMessage('Daily Reminder', sender='billgatesms57@gmail.com', recipients=[email])
                msg.body = 'Please visit our store or make a purchase!'
                mail.send(msg)
                print(f"Reminder email sent to {email}")

        print("Task completed")

@celery.task(name='app.send_monthly_activity_report')
def send_monthly_activity_report():
    with app.app_context():
        print("Monthly Activity Report Task started")

        current_date = datetime.utcnow()
        first_day_of_month = current_date.replace(day=1)

        users = User.query.all()
        for user in users:
            username = user.username
            purchase_history = PurchaseHistory.query.filter_by(username=username)\
                .filter(PurchaseHistory.purchase_date >= first_day_of_month).all()

            if purchase_history:
                subject = 'Monthly Activity Report'
                recipient_email = user.email
                html_body = f'<h2>{subject}</h2>'
                html_body += '<table border="1">'
                html_body += '<tr><th>Email</th><th>Product Name</th><th>Quantity</th><th>Price</th><th>Total</th></tr>'

                total_expenditure = 0

                for purchase in purchase_history:
                    quantity = purchase.quantity
                    price = purchase.product_price
                    total = quantity * price
                    total_expenditure += total

                    html_body += (
                        f'<tr><td>{recipient_email}</td>'
                        f'<td>{purchase.product_name}</td>'
                        f'<td>{quantity}</td>'
                        f'<td>Rs.{price:.2f}</td>'
                        f'<td>Rs.{total:.2f}</td></tr>'
                    )

                html_body += '</table>'
                html_body += f'<p>Total Expenditure: ${total_expenditure:.2f}</p>'

                msg = FlaskMailMessage(subject, sender='billgatesms57@gmail.com', recipients=[recipient_email])
                msg.html = html_body
                mail.send(msg)

                print(f"Monthly Activity Report email sent to {recipient_email}")

        print("Monthly Activity Report Task completed")



@celery.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(crontab(hour=19, minute=18), send_daily_reminders.s())
    sender.add_periodic_task(crontab(hour=19, minute=18), send_monthly_activity_report.s())

