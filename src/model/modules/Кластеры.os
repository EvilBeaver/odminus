
Функция Инициализировать() Экспорт

	Возврат Настройки.ИнициализироватьТаблицу(СтруктураФайлаХранения());	

КонецФункции

Функция СтруктураФайлаХранения()

	Массив = Новый Массив();
	Массив.Добавить("Идентификатор");
	Массив.Добавить("ИмяКластера");
	Массив.Добавить("Компьютер");
	Массив.Добавить("Порт");
	Массив.Добавить("РП_ИнтервалПерезапуска");
	Массив.Добавить("РП_ДопустимыйОбъемПамяти");
	Массив.Добавить("РП_ИнтервалПревышенияДопустимогоОбъемаПамяти");
	Массив.Добавить("РП_ДопустимоеОтклонениеКоличестваОшибокСервера");
	Массив.Добавить("РП_ПринудительноЗавершатьПроблемныеПроцессы");
	Массив.Добавить("ВыключенныеПроцессыОстанавливатьЧерез");
	Массив.Добавить("УровеньОтказоустойчивойсти");
	Массив.Добавить("РежимРаспределенияНагрузки");

	Массив.Добавить("ИдентификаторСервера");
	Массив.Добавить("НаименованиеСервера");
	Массив.Добавить("ИдентификаторСлужбы");

	Возврат Массив;

КонецФункции

Функция ПолучитьСписок(ТекущиеНастройки = Неопределено) Экспорт
	
	Если ТекущиеНастройки = Неопределено Тогда
		ДанныеКластеров = Настройки.ПолучитьНастройки("Кластеры");
	Иначе
		ДанныеКластеров = ТекущиеНастройки["Кластеры"];
	КонецЕсли;
	
	ТаблицаКластеров = Инициализировать();

	Для Каждого ДанныеКластера Из ДанныеКластеров Цикл
		ЗаполнитьЗначенияСвойств(ТаблицаКластеров.Добавить(), ДанныеКластера);
	КонецЦикла;

	Возврат ТаблицаКластеров;

КонецФункции

Функция ОбновитьДанныеКластера(ДанныеКластера, ТекущиеНастройки, ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы) Экспорт

	ТаблицаКластеров = ПолучитьСписок(ТекущиеНастройки);

	Кластер = ТаблицаКластеров.Добавить();
	Кластер.Идентификатор = Новый УникальныйИдентификатор();

	Кластер.ИмяКластера = ДанныеКластера.Name;
	Кластер.Компьютер = ВРег(ДанныеКластера.HostName);
	Кластер.Порт = ДанныеКластера.Port;
	Кластер.РП_ИнтервалПерезапуска = ДанныеКластера.RestartInterval;
	Кластер.РП_ДопустимыйОбъемПамяти = ДанныеКластера.AllowedMemory;
	Кластер.РП_ИнтервалПревышенияДопустимогоОбъемаПамяти = ДанныеКластера.ExceedingInterval;
	Кластер.РП_ДопустимоеОтклонениеКоличестваОшибокСервера = 999;
	Кластер.РП_ПринудительноЗавершатьПроблемныеПроцессы = Истина;
	Кластер.ВыключенныеПроцессыОстанавливатьЧерез = ДанныеКластера.DisabledProcessesAfter;
	Кластер.УровеньОтказоустойчивойсти = ДанныеКластера.FailOverLevel;
	Кластер.РежимРаспределенияНагрузки = ДанныеКластера.PerformanceMode;

	Кластер.ИдентификаторСервера = ИдентификаторСервера;
	Кластер.НаименованиеСервера = НаименованиеСервера;
	Кластер.ИдентификаторСлужбы = ИдентификаторСлужбы;

	ТекущиеНастройки.Кластеры = ТаблицаКластеров;

	Возврат Кластер.Идентификатор;

КонецФункции
