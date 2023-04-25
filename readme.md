# Реагирование на инциденты (события типа инцидент) из SIEM

# Для использования скрипта, необходимо:

#### Код представлен исключительно в ознакомительных целях.
#### ВАЖНО : Ваш сервер должен отвечать пайплайну максимально быстро, используйте потоки и кеширование!!!


![](static/img.png)

1) Заполнить файл конфигурации webhooks-ldaps.config данными от LDAP и Telegram
2) Запустить файлы webhook-ldaps и webhooks-bot на интеграционном сервере
3) Добавить в блок emit интересующе корреляции следующий код:

```
emit {
    # ..... initial emit code: $correlation_type = "incident"
    
    # Response
    $args = http_args_append("", "payload", join([$correlation_name, $subject.name, $subject.domain, $src.host, $dst.host], "|"))
    $response = http_get("http://webhook.integration-api.server.org:5081/getEndpoint", $args)

    # ..... over emit code (Можно использовать ответ полученный в переменную $response)
}
```

4) Указать вместо `webhook.integration-api.server.org` адрес интеграционного сервера
5) Блок join можно дополнить нужными полями события и добавить их обработку на стороне сервера интеграции
6) Провалидировать и применить правило
7) Проверить работу

#### Данная интеграция реализует следующую схему:

![](static/img_1.png)
