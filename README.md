# Инструмент фаззинга для поиска уязвимостей без исходных кодов

Данный проект представляет собой инструмент для автоматизированного поиска уязвимостей в исполняемых файлах путем фаззинг-тестирования. Инструмент работает с бинарными файлами без доступа к исходному коду программы, используя мутации входных данных для выявления потенциальных проблем безопасности.

## Описание

Основная цель - поиск уязвимостей в бинарных файлах без доступа к исходному коду с помощью техник фаззинга входных данных.

Фаззинг-тестирование проводится путём манипуляции конфигурационными файлами, которые подаются на вход исполняемым программам. Программа отслеживает падения и сбои в исполняемых файлах и записывает успешные мутации, вызвавшие эти сбои, что помогает выявить уязвимости.

## Основные функции

- Мутация входных конфигурационных файлов различными способами:
  - Замена отдельных байтов
  - Замена последовательности байтов
  - Добавление данных в конец файла
  - Вставка граничных значений
- Запуск исполняемых файлов с мутированными данными
- Сбор информации о сбоях в работе программы
- Анализ покрытия кода с использованием инструмента DynamoRIO
- Сохранение успешных мутаций и информации о найденных уязвимостях


## Требования

- Windows 10/11
- Установленный инструмент DynamoRIO
- Права администратора для запуска некоторых функций

## Использование

1. Запустите программу `fuzz.exe`
2. Выберите уязвимую программу для тестирования из списка
3. Запустите процесс фаззинга командой `fuzz`
4. Программа выполнит заданное количество мутаций (по умолчанию 300)
5. Результаты будут записаны в соответствующие лог-файлы

### Пример команды для запуска:

```
fuzz.exe
```

После запуска появится меню, где можно выбрать нужную команду.

