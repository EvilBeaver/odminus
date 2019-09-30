# Odminus

Консоль администрирования серверов 1С:Предприятия с человеческим лицом.

## Сборка и запуск

``` bash

# сборка
git clone https://github.com/EvilBeaver/odminus.git
cd odminus/src
opm install -l

# запуск
cd ..
docker build -t odminus .
docker run -p 0.0.0.0:5000:5000 -d odminus
``
