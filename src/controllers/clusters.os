
Функция Index() Экспорт
	
	ТаблицаКластеров = Кластеры.ПолучитьСписок();
	Возврат Представление(ТаблицаКластеров);
	
КонецФункции

Функция Edit() Экспорт

	Идентификатор = ЗначенияМаршрута["id"];
	Если Идентификатор = Неопределено Тогда
		Возврат Перенаправление("/cluster/index");
	КонецЕсли;

	ИдентифкаторКластера = Новый УникальныйИдентификатор(Идентификатор);

	ТЗ      = Кластеры.ПолучитьСписок();
	Элемент = ТЗ.Найти(ИдентифкаторКластера, "Идентификатор");

	Если Элемент = Неопределено Тогда
		Возврат КодСостояния(404);
	КонецЕсли;

	Если ЗапросHttp.Метод = "POST" Тогда
		Возврат Перенаправление("/cluster/index");
	Иначе
		// Передаем в представление "модель" - Элемент
		Возврат Представление("Item", Элемент);
	КонецЕсли;

КонецФункции
