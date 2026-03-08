import requests
import os
from dotenv import load_dotenv

# Загружаем .env файл и получаем из него ключ api
load_dotenv()
api_key = os.getenv("API_KEY")

if not api_key:
    raise ValueError("API_KEY не установлен в env!")

# Спрашиваем город
city = input("Введите название города: ")

# Формируем url для запроса
url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units=metric"
try:
    # Отправляем запрос в API
    response = requests.get(url)
    
    # Проверяем HTTP-код ответа 200 - город найден и данные получены
    if response.status_code == 200:

        # Пытаемся преобразовать ответ в объект json
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            print(f"Ошибка при преобразовании в JSON: {e}")
            exit()

        # Получаем данные
        temperature = data["main"]["temp"]
        description = data["weather"][0]["description"]
        
        # Выводим результат
        print(f"Температура: {temperature} С")
        print(f"Описание: {description}")
    
    # Проверяем HTTP-код ответа 404 - возвращается если город не найден
    elif response.status_code == 404:
        print("Не найден город.")
    else:
        print(f"Ошибка получения данных: {response.status_code}")

except Exception as e:
    print(f"Ошибка: {e}")
