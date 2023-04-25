import json
import random
import threading
from datetime import time, datetime
import logging.handlers

import ldap3
import nest_asyncio
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import logging
import asyncio
import sqlite3
from telegram import Update, ForceReply, InlineKeyboardButton, InlineKeyboardMarkup
# import aiogram
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackContext, filters, Application, CallbackQueryHandler  # Filters,

import time
from flask import Flask, request

# Настройка логирования
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
import logging

logger = logging.getLogger()
logging.disable(logging.CRITICAL)
logging.disable(logging.ERROR)

response = "aproove"  # instant / aproove

locks_account = {}

with open('webhooks-ldaps.config.json') as config_file:
    config_data = json.load(config_file)

bot_token = config_data['bot_token']
admin_chat_id = config_data['admin_chat']  # ID чата куда слать сообщения


def add_lock_request(src_host, dst_host, subject_name, correlation_name):
    with sqlite3.connect('locks.db') as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS lock_request ('
                       'id INTEGER PRIMARY KEY,'
                       'src_host TEXT NOT NULL,'
                       'dst_host TEXT NOT NULL,'
                       'subject_name TEXT NOT NULL,'
                       'correlation_name TEXT NOT NULL)')
        cursor.execute('INSERT INTO lock_request (src_host, dst_host, subject_name, correlation_name) '
                       'VALUES (?, ?, ?, ?)', (src_host, dst_host, subject_name, correlation_name))
        conn.commit()


def get_last_id():
    with sqlite3.connect('locks.db') as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS lock_request ('
                       'id INTEGER PRIMARY KEY,'
                       'src_host TEXT NOT NULL,'
                       'dst_host TEXT NOT NULL,'
                       'subject_name TEXT NOT NULL,'
                       'correlation_name TEXT NOT NULL)')
        cursor.execute('SELECT MAX(id) FROM lock_request')
        row = cursor.fetchone()
        return row[0] if row and row[0] else 0



async def response_button(update, context):

    if not context:
        return
    query = update.callback_query
    msg_id = query.message.id
    data = str(query.data)
    current_msg = query.message.text

    try:
        await query.answer()

        if data.startswith('read_'):
            response_id = data.replace("read_", "")
            print(f"События с ID: {response_id} отмечены как изученные инженером.")
            new_msg = f"{current_msg}\nИнцидент отмечен как изученный инженером ✅!\n"

            await application.bot.edit_message_text(text=new_msg, message_id=msg_id, chat_id=admin_chat_id)

            return True
        elif data.startswith('lock_'):
            response_id = data.replace("lock_", "")
            print(f"response_id={response_id}")

            account_to_lock = locks_account[response_id]
            subject_name = account_to_lock["subject_name"]
            src_host = account_to_lock["src_host"]
            dst_host = account_to_lock["dst_host"]
            print(f"dst_host={dst_host}, src_host={src_host}, subject_name={subject_name}")

            new_msg = f"{current_msg}\nУчетная запись {subject_name} и узлы {src_host}, {dst_host} заблокированы ⛔!\n"

            await application.bot.edit_message_text(text=new_msg, message_id=msg_id, chat_id=admin_chat_id)

            ldap_response(dst_host=dst_host, src_host=src_host, subject_name=subject_name)
            return True
        return True
    except Exception as e:
        print(f"exception: {e}")
        return True


def error_handler(update, context):
    """Log the error and send a message to the user."""
    logger.warning('Update "%s" caused error "%s"', update, context.error)
    ""


def start(update, context):
    update.message.reply_text('Hello! Welcome to my bot.')



application = Application.builder().token(bot_token).read_timeout(2).write_timeout(2).build()


syslog_server = "10.10.10.250"  # Адрес MPAgent на котором запущен syslog


app = Flask(__name__)

events = []

logger = logging.getLogger("PTGetADDate")
logger.setLevel(logging.DEBUG)


def sendSyslog(msg, delay):
    print(f"Формируется сообщение :{str(datetime.now())}")
    time.sleep(delay)
    # BUILD
    newloggerid = ''.join(random.choice('abcdef1234567890') for _ in range(7))
    logger = f'logger_{newloggerid}'
    syslog = logging.getLogger(logger)
    handler = logging.handlers.SysLogHandler(address=(syslog_server, 514))

    # SEND
    syslog.setLevel(logging.INFO)
    syslog.addHandler(handler)
    syslog.info(msg)
    print(f"Передано сообщение :{str(datetime.now())}")


def collect(target, settings, savepoint):
    for msg in events:
        msgtime = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        yield {
            "action"            : "login",
            "src.ip"            : msg["ip"],
            "event_src.host"    : msg["host"],
            "subject"           : "account",
            "subject.name"      : msg["subject"],
            "object.name"       : msg["object"],
            "status"            : "success",
            "event_src.category": "Other",
            "event_src.title"   : msg["payload"]["title"],
            "event_src.vendor"  : msg["payload"]["vendor"],
            "importance"        : "info",
            "msgid"             : msg["uuid"],
            "object.type"       : "normalize",
            "time"              : msgtime
        }
        events.remove(msg)

    # has_more is False
    yield False

    # savepoint is not modified
    yield None


@app.route('/')
def hello():
    return 'root of hooks. hi!'


@app.route('/eventsEndpoint', methods=['POST'])
def eventsEndpoint():
    print(request)
    return "good"


@app.route('/getEndpoint', methods=['GET'])
def getEndpoint(): # async
    try:
        # print(request)
        data = request.args['payload']
        correlation_name = data.split("|")[0]
        subject_name = data.split("|")[1]
        subject_domain = data.split("|")[2]
        src_host = data.split("|")[3]
        dst_host = data.split("|")[4]

        print(f"Response fired for:\n"
              f"Correlation {correlation_name}.\n"
              f"Subject: {subject_name}.\n"
              f"Domain: {subject_domain}.\n"
              f"src: {src_host}.\n"
              f"dst: {dst_host}.")
        print(f"Account will be blocked in LDAP: {subject_name}")

        add_lock_request(src_host=src_host, dst_host=dst_host, subject_name=subject_name, correlation_name=correlation_name)
        current_id = get_last_id()

        text = f"🚨PT MaxPatrol SIEM🚨:\n---\nСобытие номер: {current_id}\n---\n" \
               f"-> Правило: {correlation_name}\n---\n" \
               f"⚠️Обнаружен успешный подбор учетной записи!\n---\n" \
               f"👤 Учетная запись: {subject_name}\n" \
               f"💻 Узел источник: {src_host}\n" \
               f"🖥️ Целевой узел: {dst_host}\n---\n"

        if response == "instant":
            ldap_response(dst_host, src_host, subject_name)
            text += f"Учетная запись и оба узла заблокированы ⛔!\n"

            try:
                asyncio.run(application.bot.send_message(chat_id=admin_chat_id, text=text))
            except:
                ""
        else:
            locks_account[str(current_id)] = {"dst_host": dst_host, "src_host": src_host, "subject_name": subject_name}

            keyboard = [[InlineKeyboardButton("Рассмотрено ✅", callback_data=f"read_{current_id}"),
                         InlineKeyboardButton("Заблокировать ❌", callback_data=f"lock_{current_id}")]]

            reply_markup = InlineKeyboardMarkup(keyboard)

            try:
                asyncio.run(application.bot.send_message(chat_id=admin_chat_id, text=text, reply_markup=reply_markup))
            except:
                ""
        syslog_msg = """{"payload": {"title": f"Response on account {subject_name}.", "vendor": "Positive"}, "ip": "10.10.10.10",
                        "host"   : src_host, "subject": "account", "object": "host",
                        "uuid"   : "02d4f5fd-46c8-48ac-851c-6c45e10a240d", "time": "1661940112"}"""

        sendSyslog(syslog_msg.replace("{subject_name}", subject_name), 0)

        return "response OK"
    except Exception as e:
        print(f"Execption: {e}")
        return "response not OK."


def ldap_response(dst_host, src_host, subject_name):
    print(f"ldap_response fired: subject_name={subject_name}, src_host={src_host}, dst_host={dst_host}")
    server_address = 'ldaps://10.10.10.10'
    username = config_data['ldap_user']
    password = config_data['ldap_password']
    dn = 'OU=siem-response,OU=pt,OU=Технические УЗ,DC=z-lab,DC=me'
    server = Server(server_address, get_info=ALL)
    conn = Connection(server, user=username, password=password, auto_bind=True)
    accounts = [subject_name, f"{src_host}$", f"{dst_host}$"]
    for account_to_disable in accounts:
        conn.search(dn, f'(sAMAccountName={account_to_disable})', ldap3.SUBTREE, attributes=['objectClass'])

        if conn.entries:
            account_dn = conn.entries[0].entry_dn
            print(f'Account {account_to_disable} DN is: {account_dn}.')
            account_classes = conn.entries[0]['objectClass'].values
            account_class = "computer" if "computer" in account_classes else "user"
            block_code = 2 if account_class == "computer" else 514
            print(f'Account {account_to_disable} class is: {account_class}.')

            return_code = conn.modify(account_dn, {'userAccountControl': [(MODIFY_REPLACE, [f'{block_code}'])]})
            print(f'Account {account_to_disable} has been disabled.')
            print(f"Account blocked action ended on: {account_to_disable}. Return code: {return_code}")
        else:
            print(f'User {account_to_disable} not found.')
    conn.unbind()

    """
    response = requests.get(
            "https://api.telegram.org/botAPI_KEY/sendMessage",
            params={"chat_id": 45251901, "text": f"🚨PT MaxPatrol SIEM🚨:\n---\n"
                                                 f"⚠️Обнаружен успешный подбор учетной записи!\n---\n"
                                                 f"👤 Учетная запись: {subject_name}\n"
                                                 f" 💻 Узел источник: {src_host}\n"
                                                 f" 🖥️ Целевой узел: {dst_host}\n---\n"
                                                 f"Учетная запись и оба узла заблокированы ⛔!\n"},
    )
    """


nest_asyncio.apply()


async def web():
    app.run(debug=False, host='10.10.10.196', port=5081, use_reloader=False)


print("run_api_server")
# app.run(debug=False, host='10.10.10.196', port=5081, use_reloader=False)
threading.Thread(target=lambda: app.run(debug=False, host='10.10.10.196', port=5081, use_reloader=False)).start()

print("telegram_bot")
application.run_polling(timeout=86000, poll_interval=86000, pool_timeout=86000)
# executor.start_polling(dp)

