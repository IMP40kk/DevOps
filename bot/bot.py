import logging
import re
import paramiko
import psycopg2
import os
import subprocess
from dotenv import load_dotenv
from psycopg2 import Error

from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext

load_dotenv()

TOKEN = os.getenv('TOKEN')


logger = logging.getLogger(__name__)

VERIFY_PASS = range(1)
def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!')


def helpCommand(update: Update, context: CallbackContext) -> None:
    commands = [
        '/start - Начать общение с ботом',
        '/help - Показать эту справку',
        'Команды для работы с БД',
        '/get_emails - Получить все сохраненные email адреса из БД',
        '/get_phone_numbers - Получить все сохраненные номера телефонов из БД',
        '/find_phone_number - Найти телефонные номера в тексте',
        '/find_email - Найти email адреса в тексте',
        '/get_repl_logs - Получить логи репликации',
        'Остальные команды',
        '/verify_password - Проверить сложность пароля',
        '/get_release - Получить информацию о версии системы',
        '/get_uname - Получить информацию об архитектуре системы',
        '/get_uptime - Получить информацию о времени работы системы',
        '/get_df - Получить информацию о состоянии файловой системы',
        '/get_free - Получить информацию о состоянии оперативной памяти',
        '/get_vmstat - Получить информацию о производительности системы',
        '/get_w - Получить информацию о работающих пользователях',
        '/get_auths - Получить информацию о последних входах в систему',
        '/get_critical - Получить информацию о последних критических событиях',
        '/get_ps - Получить информацию о запущенных процессах',
        '/get_ss - Получить информацию об используемых портах',
        '/get_services - Получить информацию о статусе всех служб',
        '/get_apt_list - Получить информацию о пакетах'
    ]
    update.message.reply_text("\n".join(commands))


def findPhoneNumbersCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')

    return 'findPhoneNumbers'


def findEmailCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска email адресов: ')

    return 'findEmails'



def verifyPassCommand(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('Введите пароль:')
    return VERIFY_PASS

def verifyPass(update: Update, context: CallbackContext) -> int:
    user_input = update.message.text
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$'
    
    # Проверка пароля на соответствие паттерну
    if re.match(pattern, user_input):
        update.message.reply_text("Пароль сложный.")
    else:
        update.message.reply_text("Пароль простой.")
    
    return ConversationHandler.END

def cancel(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('Проверка пароля отменена.')
    return ConversationHandler.END

found_phone_numbers = ''


def confirm_phones_database_write(update, context):
    user_response = update.message.text
    if user_response == 'Да' or user_response == 'Д' or user_response == 'да' or user_response == 'ДА':
        connection = None
        try:
            connection = psycopg2.connect(user=os.getenv('DB_USER'),
                                          password=os.getenv('DB_PASSWORD'),
                                          host=os.getenv('DB_HOST'),
                                          port=os.getenv('DB_PORT'),
                                          database=os.getenv('DB_DATABASE'))

            cursor = connection.cursor()
            cleaned_numbers_list = re.findall(
                r'\+?7[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|\+?7[ -]?\d{10}|\+?7[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}|8[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|8[ -]?\d{10}|8[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}',
                found_phone_numbers)
            for phone_number in cleaned_numbers_list:
                cursor.execute("INSERT INTO phone_numbers (phone_number) VALUES (%s);", (phone_number,))
            connection.commit()
            logging.info("Команда успешно выполнена")
        except (Exception, Error) as error:
            logging.error("Ошибка при работе с PostgreSQL: %s", error)
        finally:
            if connection is not None:
                cursor.close()
                connection.close()
        update.message.reply_text("Найденные номера успешно записаны в базу данных.")
    else:
        update.message.reply_text("Найденные номера не записаны в базу данных.")

    return ConversationHandler.END


found_emails = ''


def confirm_emails_database_write(update, context):
    user_response = update.message.text
    if user_response == 'Да' or user_response == 'Д' or user_response == 'да' or user_response == 'ДА':
        connection = None
        try:
            connection = psycopg2.connect(user=os.getenv('DB_USER'),
                                          password=os.getenv('DB_PASSWORD'),
                                          host=os.getenv('DB_HOST'),
                                          port=os.getenv('DB_PORT'),
                                          database=os.getenv('DB_DATABASE'))

            cursor = connection.cursor()
            cleaned_email_list = re.findall(
                r'\b[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+)*' \
                r'@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', found_emails)
            for email_adr in cleaned_email_list:
                cursor.execute("INSERT INTO emails (email) VALUES (%s);", (email_adr,))
            connection.commit()
            logging.info("Команда успешно выполнена")
        except (Exception, Error) as error:
            logging.error("Ошибка при работе с PostgreSQL: %s", error)
        finally:
            if connection is not None:
                cursor.close()
                connection.close()
        update.message.reply_text("Найденные email адреса успешно записаны в базу данных.")
    else:
        update.message.reply_text("Найденные email адреса не записаны в базу данных.")

    return ConversationHandler.END


def findPhoneNumbers(update: Update, context):
    user_input = update.message.text  # Получаем текст, содержащий(или нет) номера телефонов

    # Модифицированные регулярные выражения
    phoneNumRegex1 = re.compile(r'(?<!\d)(?:\+?7|8)[\s(]?(?!\d{19})\d{1,3}[\s)]?\d{1,3}[\s-]?\d{2}[\s-]?\d{2}\b')
    phoneNumRegex2 = re.compile(r'\b(?:\+?7|8)[\s-]?(?!\d{19})\d{1,3}[\s-]?\d{1,3}[\s-]?\d{2}[\s-]?\d{2}\b')

    phoneNumberSet = set()  # For normalized numbers
    phoneNumbers = []       # For original numbers

    def normalize_phone_number(phone_num):
        # Normalize by removing non-numeric characters except leading +
        if phone_num.startswith('+'):
            return '+' + re.sub(r'\D', '', phone_num[1:])
        else:
            return re.sub(r'\D', '', phone_num)

    for phone_num in phoneNumRegex1.findall(user_input) + phoneNumRegex2.findall(user_input):
        normalized = normalize_phone_number(phone_num)
        if len(normalized) == 12 or (len(normalized) == 11 and normalized.startswith('8')):  # Проверяем длину номера
            if normalized not in phoneNumberSet:
                phoneNumberSet.add(normalized)
                phoneNumbers.append(phone_num)  # Save the original format

    if not phoneNumbers:  # Обрабатываем случай, когда номеров телефонов нет
        update.message.reply_text('Телефонные номера не найдены')
        return ConversationHandler.END

    phoneNumbersStr = '\n'.join(phoneNumbers)  # Преобразуем список в строку

    global found_phone_numbers
    found_phone_numbers = phoneNumbersStr
    update.message.reply_text(phoneNumbersStr)  # Отправляем сообщение пользователю
    update.message.reply_text("Хотите записать найденные номера в БД [Да] / [Нет]:")
    return 'confirm_database_write'


def findEmails(update: Update, context: CallbackContext) -> str:
    user_input = update.message.text

    email_regex = re.compile(
        r'\b[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+)*'
        r'@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    email_list = email_regex.findall(user_input)

    # Используем set для хранения уникальных email
    unique_emails = set(email_list)

    if not unique_emails:
        update.message.reply_text('Email адреса не найдены')
        return ConversationHandler.END

    email_addresses = '\n'.join(unique_emails)

    global found_emails
    found_emails = email_addresses
    update.message.reply_text(email_addresses)
    update.message.reply_text("Хотите записать найденные email адреса в БД  [Да] / [Нет]:")
    return 'confirm_emails_database_write'
    


def echo(update: Update, context: CallbackContext) -> None:
    update.message.reply_text(
        "Неизвестная команда. Пожалуйста, используйте /find_email, /find_phone_number")


def execute_ssh_command(command):
    host = os.getenv('RM_HOST')
    port = os.getenv('RM_PORT')
    username = os.getenv('RM_USER')
    password = os.getenv('RM_PASSWORD')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(hostname=host, username=username, password=password, port=port)

    stdin, stdout, stderr = client.exec_command(command)
    data = stdout.read() + stderr.read()

    client.close()

    data = str(data, 'utf-8').strip()
    return data


def printPrtData(update: Update, data):
    max_message_length = 4096
    parts = [data[i:i + max_message_length] for i in range(0, len(data), max_message_length)]
    for part in parts:
        update.message.reply_text(part)


def get_release(update: Update, context: CallbackContext) -> None:
    release_info = execute_ssh_command('lsb_release -a')
    update.message.reply_text(release_info)


# Команда для получения информации об архитектуре процессора, имени хоста системы и версии ядра
def get_uname(update: Update, context: CallbackContext) -> None:
    uname_info = execute_ssh_command('uname -a')
    update.message.reply_text(uname_info)


# Команда для получения информации о времени работы системы
def get_uptime(update: Update, context: CallbackContext) -> None:
    uptime_info = execute_ssh_command('uptime')
    update.message.reply_text(uptime_info)


# Команда для получения информации о состоянии файловой системы
def get_df(update: Update, context: CallbackContext) -> None:
    df_info = execute_ssh_command('df -h')
    update.message.reply_text(df_info)


# Команда для получения информации о состоянии оперативной памяти
def get_free(update: Update, context: CallbackContext) -> None:
    free_info = execute_ssh_command('free -m')
    update.message.reply_text(free_info)


# Команда для получения информации о производительности системы
def get_vmstat(update: Update, context: CallbackContext) -> None:
    vmstat_info = execute_ssh_command('vmstat')
    update.message.reply_text(vmstat_info)


# Команда для получения информации о работающих пользователях
def get_w(update: Update, context: CallbackContext) -> None:
    w_info = execute_ssh_command('w')
    update.message.reply_text(w_info)


# Команда для получения информации о последних входах в систему
def get_auths(update: Update, context: CallbackContext) -> None:
    auths_info = execute_ssh_command('last -n 10')
    update.message.reply_text(auths_info)


# Команда для получения информации о последних критических событиях
def get_critical(update: Update, context: CallbackContext) -> None:
    critical_info = execute_ssh_command('journalctl -p crit -n 5')
    update.message.reply_text(critical_info)


# Команда для получения информации о запущенных процессах
def get_ps(update: Update, context: CallbackContext) -> None:
    ps_info = execute_ssh_command('ps aux | head -n 10')
    update.message.reply_text(ps_info)


# Команда для получения информации об используемых портах
def get_ss(update: Update, context: CallbackContext) -> None:
    ss_info = execute_ssh_command('ss -tuln')
    update.message.reply_text(ss_info)


def get_repl_logs(update: Update, context):
    printPrtData(update, subprocess.run("cat /var/log/postgresql/postgresql.log | grep repl", shell=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip('\n'))


# Функция обработки команды /get_emails
def get_emails(update: Update, context: CallbackContext) -> None:
    def connect_to_db():
        return psycopg2.connect(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT'),
            database=os.getenv('DB_DATABASE')
        )

    try:
        connection = connect_to_db()
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM emails;")
        emails = cursor.fetchall()
        if emails:
            email_list = "\n".join(email[0] for email in emails)
            update.message.reply_text(f"Email адреса:\n{email_list}")
        else:
            update.message.reply_text("В базе данных нет email адресов.")
    except Exception as e:
        logging.error(f"Ошибка при работе с PostgreSQL: {str(e)}")
        update.message.reply_text(f"Произошла ошибка: {str(e)}")
    finally:
        if connection is not None:
            cursor.close()
            connection.close()


# Функция обработки команды /get_phone_numbers
def get_phone_numbers(update: Update, context: CallbackContext) -> None:
    connection = None

    try:
        # Подключение к базе данных
        connection = psycopg2.connect(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT'),
            database=os.getenv('DB_DATABASE')
        )

        cursor = connection.cursor()
        cursor.execute("SELECT phone_number FROM phone_numbers;")
        phone_numbers = cursor.fetchall()

        if phone_numbers:
            phone_number_list = "\n".join(phone_number[0] for phone_number in phone_numbers if phone_number)
            update.message.reply_text(f"Номера телефонов:\n{phone_number_list}")
        else:
            update.message.reply_text("В базе данных нет номеров телефонов.")
    except Exception as e:
        logging.error(f"Ошибка при работе с PostgreSQL: {str(e)}")
        update.message.reply_text(f"Произошла ошибка: {str(e)}")
    finally:
        if connection is not None:
            cursor.close()
            connection.close()


def get_apt_list(update: Update, context):
    if context.args:
        package_name = ' '.join(context.args)
        printPrtData(update, execute_ssh_command(f'dpkg -l | grep "{package_name}"'))
    else:
        printPrtData(update, execute_ssh_command('dpkg -l'))


def get_services(update: Update, context):
    printPrtData(update, execute_ssh_command('service --status-all'))


def main():
    updater = Updater(TOKEN, use_context=True)

    # Получаем диспетчер для регистрации обработчиков
    dp = updater.dispatcher

    # Обработчик диалога
    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_number', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
            'confirm_database_write': [MessageHandler(Filters.text & ~Filters.command, confirm_phones_database_write)]
        },
        fallbacks=[]
    )

    convHandlerFindEmail = ConversationHandler(
        entry_points=[CommandHandler('find_email', findEmailCommand)],
        states={
            'findEmails': [MessageHandler(Filters.text & ~Filters.command, findEmails)],
            'confirm_emails_database_write': [
                MessageHandler(Filters.text & ~Filters.command, confirm_emails_database_write)]
        },
        fallbacks=[]
    )
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPassCommand)],
        states={
            VERIFY_PASS: [MessageHandler(Filters.text & ~Filters.command, verifyPass)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
  

    # Регистрируем обработчики команд
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmail)
    dp.add_handler(conv_handler)
   
    dp.add_handler(CommandHandler("get_release", get_release))
    dp.add_handler(CommandHandler("get_uname", get_uname))
    dp.add_handler(CommandHandler("get_uptime", get_uptime))
    dp.add_handler(CommandHandler("get_df", get_df))
    dp.add_handler(CommandHandler("get_free", get_free))
    dp.add_handler(CommandHandler("get_vmstat", get_vmstat))
    dp.add_handler(CommandHandler("get_w", get_w))
    dp.add_handler(CommandHandler("get_auths", get_auths))
    dp.add_handler(CommandHandler("get_critical", get_critical))
    dp.add_handler(CommandHandler("get_ps", get_ps))
    dp.add_handler(CommandHandler("get_ss", get_ss))
    dp.add_handler(CommandHandler("get_services", get_services))
    dp.add_handler(CommandHandler("get_apt_list", get_apt_list))
    dp.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))

    # Регистрируем обработчик текстовых сообщений
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    # Запускаем бота
    updater.start_polling()

    # Останавливаем бота при нажатии Ctrl+C
    updater.idle()


if __name__ == '__main__':
    main()
