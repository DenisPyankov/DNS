# DNS сервер
Кэширующий DNS сервер. Сервер прослушивает 53 порт. При первом запуске кэш пустой. Сервер получает от клиента рекурсивный запрос и выполняет разрешение запроса. Получив ответ, сервер разбирает пакет ответа. Полученная информация сохраняется в кэше сервера. При повторных запусках
сервер считывает данные с диска и удаляет просроченные записи, инициализирует таким образом свой кэш.

# Пример использования 
запускаем файл "CDNS.py"

# 1
![1](https://github.com/DenisPyankov/DNS/assets/91528031/0fe95838-3616-477a-bb2d-14bf301b0184)

# 2
![2 1](https://github.com/DenisPyankov/DNS/assets/91528031/4390f9b2-f442-4489-87ba-37775ba6b5c6)
![2 2](https://github.com/DenisPyankov/DNS/assets/91528031/a57a1daa-6d76-4176-8db9-0cb3fdd632e5)

#3
![3 1](https://github.com/DenisPyankov/DNS/assets/91528031/5ac624ce-8bf8-4fdb-bebb-a45b3d091621)
![3 2](https://github.com/DenisPyankov/DNS/assets/91528031/07cac03f-03ba-4ba6-8470-742a5c74cff2)

#4
![4 1](https://github.com/DenisPyankov/DNS/assets/91528031/a2108056-aa17-43cb-8389-60de547c8b02)
![4 2](https://github.com/DenisPyankov/DNS/assets/91528031/c360958a-cc05-4fee-88cd-2873a5221a04)



