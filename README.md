# SecureChat

### Русский:

Мессенджер, написанный на питоне, для GUI использовалась библиотека Tkinter.
В нём есть:
- Шифрование отправляемых сообщений.
- Полноценная передача файлов, с возможностью их шифрования при отправке.
- Возможность изменять цвет текста, и цвет фона.
  Что-бы изменить цвет текста, нужно поставить амперсанд (  & ),
  написать название цвета ( на английском ), поставить еще один амперсанд,
  написать текст, который должен быть цветным, и поставить последний, закрывающий амперсанд.
  В итоге это должно выглядеть примерно так
  ```
  Использование:
  &название_цвета&текст&
  Пример:
  &yellow&Всем привет!&
  
  Также, можно изменить цвет фона, для этого вместо амперсанда поставьте ^
  Использование:
  ^название_цвета^текст^
  Пример:
  ^yellow^Всем привет!^
  ```
  
Для запуска просто запустите файл Chat.pyw, но лучше запускайте "Start chat with debug console.bat", ведь если вы встретите какой-то баг, то сможете отправить мне логи.

Приятного пользования!

### English:
Messenger written using python, and Tkinter library for GUI.
It has:
- Encryption of sent messages.
- Full file transfer, with the ability to encrypt when sending.
- Ability to change text and background color.
  To change the color of the text, you need to put an ampersand ( & ),
  write the name of the color (in English), put another ampersand,
  write the text, which should be colored, and put the last, closing ampersand.
  In the end, it should look something like this
  ```
  Using:
  &color_name&text&
  Example:
  &yellow&Hello everyone!&
  
  Also, you can change the background color, for this, instead of the ampersand, put ^
  Using:
  ^color_name^text^
  Example:
  ^blue^Hello everyone!^
  ```
  
To start, just run the Chat.pyw file, but it's better to run "Start chat with debug console.bat", because if you come across some kind of bug, you can send me the logs.

Enjoy your use!
