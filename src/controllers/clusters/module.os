#Использовать irac

Процедура СформироватьБоковуюПанель(Знач АктивнаяСтрока = Неопределено)

	Панель = БоковаяПанельНавигации.ОписаниеПанели();

	БоковаяПанельНавигации.ДобавитьСсылку(Панель, АдресДействия("index"), "Кластеры серверов");
	ПараметрыСсылки = Новый Структура;
	ПараметрыСсылки.Вставить("controller","cluster-admins");
	БоковаяПанельНавигации.ДобавитьСсылку(Панель, АдресМаршрута("ПоАгенту", ПараметрыСсылки), "Администраторы");

	Если АктивнаяСтрока <> Неопределено Тогда
		Панель[АктивнаяСтрока].Активность = Истина;
	КонецЕсли;

	ДанныеПредставления["Sidebar"] = Панель;

КонецПроцедуры

Функция Index() Экспорт

	Идентификатор = ЗначенияМаршрута["agent"];
	Если Идентификатор = Неопределено Тогда
		Возврат Перенаправление("/agents/index");
	КонецЕсли;

	Элемент = ЦентральныеСерверы.ПолучитьЭлемент(Идентификатор);
	Если Элемент = Неопределено Тогда
		Возврат КодСостояния(404);
	КонецЕсли;

	СформироватьБоковуюПанель(0);

	Попытка
		Администрирование = ОбщегоНазначения.ПолучитьАдминистрированиеКластера(
			Элемент.СетевоеИмя,
			Элемент.Порт,
			"8.3"
		);
		
		Кластеры = Администрирование.Кластеры();
		МодельПредставления = Новый Структура;
		МодельПредставления.Вставить("Агент", Элемент);
		МодельПредставления.Вставить("Кластеры", Кластеры.Список());
		Возврат Представление(МодельПредставления);
	Исключение
		Возврат Представление("rasError", ОписаниеОшибки());
	КонецПопытки
КонецФункции

Функция Overview() Экспорт
	
	// в версии 0.3 доступен метод ПараметрыЗапроса()
	// а пока - парсим сами

	Параметры = ОбщегоНазначения.РазобратьПараметрыЗапроса(ЗапросHttp.СтрокаЗапроса);
	Кластер = Параметры["cluster"];
	Если Кластер = Неопределено Тогда
		Возврат Перенаправление("/");
	КонецЕсли;

	Возврат Представление(, Кластер);

КонецФункции