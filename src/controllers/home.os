
Функция Index() Экспорт

	мНастройки = Настройки.ГлобальныеНастройки;
	
	Массив = Новый Массив();
	Массив.Добавить(Новый Структура("Ключ, Значение", "Количество серверов", мНастройки["Серверы"].Количество()));
	Массив.Добавить(Новый Структура("Ключ, Значение", "Количество служб", мНастройки["Службы"].Количество()));
	Массив.Добавить(Новый Структура("Ключ, Значение", "Количество кластеров", мНастройки["Кластеры"].Количество()));

	Возврат Представление(Массив);

КонецФункции
