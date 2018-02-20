#Использовать json

Функция ЗагрузитьДанныеОтАгента(Данные) Экспорт
	
	Парсер = Новый ПарсерJSON;
	
	ПолученныеДанные = Парсер.ПрочитатьJSON(Данные,,,Истина);
	
	Если НЕ ПолученныеДанные.Свойство("Server") Тогда
		Возврат Ложь;
	КонецЕсли;
	
	ДатаОбновленияДанных = ТекущаяДата();
	
	ТекущиеНастройки = Настройки.Прочитать();
	
	ИдентификаторСервера = Серверы.ОбновитьДанныеСервера(ПолученныеДанные.Server, ТекущиеНастройки, ДатаОбновленияДанных);
	НаименованиеСервера = ВРег(ПолученныеДанные.Server.ComputerSystem.Hostname);
	
	УдалитьДанныеСервера("Службы", Службы, ТекущиеНастройки, ИдентификаторСервера);
	УдалитьДанныеСервера("Кластеры", Кластеры, ТекущиеНастройки, ИдентификаторСервера);
	
	Если ЗначениеЗаполнено(ПолученныеДанные.Services1C) Тогда
		ЗагрузитьДанныеСлужб(ПолученныеДанные.Services1C, ИдентификаторСервера, НаименованиеСервера, ТекущиеНастройки);
	КонецЕсли;
	
	Настройки.Записать(ТекущиеНастройки);
	Настройки.ТребуетсяОбновлениеНастроек = Истина;
	
	Возврат Истина;
	
КонецФункции

Процедура УдалитьДанныеСервера(ИмяНастройки, МодульНастройки, ТекущиеНастройки, ИдентификаторСервера)
	
	мНастройка = МодульНастройки.ПолучитьСписок(ТекущиеНастройки);
	НайденныеСтроки = мНастройка.НайтиСтроки(Новый Структура("ИдентификаторСервера", ИдентификаторСервера));
	
	Для Каждого Данные Из НайденныеСтроки Цикл
		мНастройка.Удалить(Данные);	
	КонецЦикла;
	
	ТекущиеНастройки[ИмяНастройки] = мНастройка;
	
КонецПроцедуры

Процедура ЗагрузитьДанныеСлужб(ПолученныеДанные, ИдентификаторСервера, НаименованиеСервера, ТекущиеНастройки)
	
	Если ТипЗнч(ПолученныеДанные) = Тип("Массив") Тогда
		Для Каждого ДанныеСлужбы Из ПолученныеДанные Цикл
			ИдентификаторСлужбы = Службы.ОбновитьДанныеСлужб(ДанныеСлужбы, ТекущиеНастройки, 
			ИдентификаторСервера, НаименованиеСервера);
			
			Если НЕ ДанныеСлужбы.Свойство("Clusters") Тогда
				Продолжить;
			КонецЕсли;
			
			ЗагрузитьДанныеКластеров(ДанныеСлужбы.Clusters, ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы, ТекущиеНастройки);
		КонецЦикла;
	Иначе
		ИдентификаторСлужбы = Службы.ОбновитьДанныеСлужб(ПолученныеДанные, 
		ТекущиеНастройки, ИдентификаторСервера, НаименованиеСервера);
		
		Если НЕ ПолученныеДанные.Свойство("Clusters") Тогда
			Возврат;
		КонецЕсли;
		
		ЗагрузитьДанныеКластеров(ПолученныеДанные.Clusters, ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы, ТекущиеНастройки);
	КонецЕсли;
	
КонецПроцедуры

Процедура ЗагрузитьДанныеКластеров(ДанныеКластеров, ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы, ТекущиеНастройки)
	
	Если ТипЗнч(ДанныеКластеров) = Тип("Массив") Тогда
		Для Каждого Данные Из ДанныеКластеров Цикл
			ИдентификаторКластера = Кластеры.ОбновитьДанныеКластера(Данные, ТекущиеНастройки, 
			ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы);
		КонецЦикла;
	Иначе
		ИдентификаторКластера = Кластеры.ОбновитьДанныеКластера(ДанныеКластеров, ТекущиеНастройки, 
		ИдентификаторСервера, НаименованиеСервера, ИдентификаторСлужбы);
	КонецЕсли;	
	
КонецПроцедуры