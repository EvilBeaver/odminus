
Функция Инициализировать() Экспорт

	Возврат Настройки.ИнициализироватьТаблицу(СтруктураФайлаХранения());	

КонецФункции

Функция СтруктураФайлаХранения()

	Массив = Новый Массив();
	Массив.Добавить("Идентификатор");
	Массив.Добавить("Наименование_1С");
	Массив.Добавить("Наименование_БД");
	Массив.Добавить("Сервер_1С");
	Массив.Добавить("Сервер_БД");
	Массив.Добавить("Тип_БД");
	Массив.Добавить("Описание");
	Массив.Добавить("РазрешитьВыдачуЛицензий");
	Массив.Добавить("БлокировкаРегламетныхЗаданий");
	Массив.Добавить("СмещениеДаты");

	Возврат Массив;

КонецФункции
