
Функция Index() Экспорт

	мНастройки = Настройки.ГлобальныеНастройки;
	
	СтруктураДанных = Новый Структура();
	СтруктураДанных.Вставить("КоличествоСерверов", мНастройки["Серверы"].Количество());
	СтруктураДанных.Вставить("КоличествоСлужб", мНастройки["Службы"].Количество());

	Массив = Новый Массив();
	Массив.Добавить(Новый Структура("Ключ, Значение", "Количество серверов", мНастройки["Серверы"].Количество()));
	Массив.Добавить(Новый Структура("Ключ, Значение", "Количество служб", мНастройки["Службы"].Количество()));

	Возврат Представление(Массив);

КонецФункции
