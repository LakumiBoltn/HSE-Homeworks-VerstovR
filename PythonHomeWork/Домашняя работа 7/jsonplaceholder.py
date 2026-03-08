import requests

# Базовый url API JSONPlaceholder
base_url = "https://jsonplaceholder.typicode.com"
# Выводимое кол-во постов
count_posts = 5

# Отправляем запрос к API
response = requests.get(f"{base_url}/posts")

# Проверяем HTTP код ответа от API
if response.status_code == 200:
    
    # Пытаемся преобразовать ответ в объект json
    try:
        posts = response.json()
    except json.JSONDecodeError as e:
        print(f"Ошибка при преобразовании в JSON: {e}")
        exit()


    # Проверяем, что posts - список
    if not isinstance(posts, list):
        print(f"Ошибка: ожидался список постов, но получен {type(posts)}")
        exit()
    
    # Првоеряем, что список постов не пустой
    if len(posts) == 0:
        print("Список постов пуст. Нечего отображать.")
        exit()

    # Если вернулось кол-во постов меньше conut_posts, то будем выводить все вернувшиеся
    posts_to_show = min(count_posts, len(posts))

    # Обходим список полученных постов (первые posts_to_show постов)
    for i in range(posts_to_show):

        # Разбираем пост
        post = posts[i]
        title = post.get("title", "Пустой заголовок")
        body = post.get("body", "Пустое тело")
        
        # Вывод
        print(f"Пост N{i+1}")
        print(f"Заголовок: {title}")
        print(f"Тело: {body}")
        print("\n")

else:
    print(f"Ошибка при выполнении запроса. Код ошибки: {response.status_code}")
