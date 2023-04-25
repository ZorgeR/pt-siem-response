import json
import logging
import sqlite3
from telegram import Update, ForceReply, InlineKeyboardButton, InlineKeyboardMarkup
# import aiogram
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackContext, filters, Application, CallbackQueryHandler  # Filters,

import ldap3
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE

with open('webhooks-ldaps.config.json') as config_file:
    config_data = json.load(config_file)

bot_token = config_data['bot_token']
admin_chat_id = config_data['admin_chat']  # ID чата куда слать сообщения

application = Application.builder().token(bot_token).read_timeout(2).write_timeout(2).build()

# Настройка логирования
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
import logging

logger = logging.getLogger()
logging.disable(logging.CRITICAL)
logging.disable(logging.ERROR)

def get_lock_requests(id):
    with sqlite3.connect('locks.db') as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS lock_request ('
                       'id INTEGER PRIMARY KEY,'
                       'src_host TEXT NOT NULL,'
                       'dst_host TEXT NOT NULL,'
                       'subject_name TEXT NOT NULL,'
                       'correlation_name TEXT NOT NULL)')
        cursor.execute("SELECT * FROM lock_request WHERE id=?", (id,))
        rows = cursor.fetchall()
        return [
            {
                'id': row[0],
                'src_host': row[1],
                'dst_host': row[2],
                'subject_name': row[3],
                'correlation_name': row[4],
            }
            for row in rows
        ]


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

            account_to_lock = get_lock_requests(response_id)

            subject_name = account_to_lock[0]["subject_name"]
            src_host = account_to_lock[0]["src_host"]
            dst_host = account_to_lock[0]["dst_host"]
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


def start(update, context):
    update.message.reply_text('Hello! Welcome to my bot.')


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
    # bot_uri
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


application.add_handler(CommandHandler('start', start))
application.add_handler(CallbackQueryHandler(response_button))
application.add_error_handler(error_handler)



print("telegram_bot")
application.run_polling(timeout=3, poll_interval=3, pool_timeout=3)

