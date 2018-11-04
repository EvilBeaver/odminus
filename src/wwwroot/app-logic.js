var logicDataList = {

    getItem_SelectDB: function () {
        return $('#select_infobase');
    },

    reloadList: function (element_select, urlRequest, clusterId) {
        $('#activity').show();
        var thisSelect = element_select.val();
        if ($('.connection').hasClass('connection-on')) {
            $.ajax({
                url: '',
                success: function (data) {
                    $('#data-list').data('table').loadData(
                        urlRequest
                        + '?cluster=' + clusterId
                        + '&db=' + thisSelect,
                        true);
                }
            });
        }
        else {
            $.ajax({
                url: '',
                success: function (data) {
                    $('#data-list').data('table').loadData(
                        urlRequest
                        + '?cluster=' + clusterId
                        + '&empty=true');
                }
            });
        }
    },

    updateStatusConnection: function (result) {
        $('.connection').removeClass('connection-off').removeClass('connection-on');
        if (result == 'Ok') {
            $('.connection').addClass('connection-on');
            $('.button-auth').css('display', 'none');
        }
        else {
            $('.connection').addClass('connection-off');
            $('.button-auth').css('display', 'block');
        }
        $('#activity').hide();
    },

    authInInfobase: function (element_select, urlRequest, clusterId) {
        var dialog = $('.dialog');
        dialog.find('div.dialog-actions > button.dialog-btn-access').click(function () {
            Metro.dialog.close(dialog);

            $('#activity').show();

            // Почему-то не парсится
            var dataAuth = {
                Пользователь: $("#db-login").val(),
                Пароль: $("#db-password").val()
            };

            var dataStr = '{"Пользователь": "' + $("#db-login").val() + '", "Пароль": "' + $("#db-password").val() + '"}';

            $.ajax({
                url: urlRequest + '?cluster=' + clusterId + '&db=' + element_select.val(),
                method: 'POST',
                data: dataStr,
                success: function (data) {
                    logicDataList.updateStatusConnection(data);
                    reloadList();
                },
                error: function (request, status, error) {
                    logicDataList.updateStatusConnection('error');
                    reloadList();
                }
            });

        });
        dialog.find('div.dialog-actions > button.dialog-btn-cancel').click(function () {
            Metro.dialog.close(dialog);
        });
        Metro.dialog.open(dialog);
    },

    selectDbOnChange: function (element_select, urlRequest, clusterId) {
        if (element_select.attr('ready') == 'true') {
            $('#activity').show();
            $.ajax({
                url: urlRequest + '?cluster=' + clusterId + '&db=' + element_select.val(),
                method: 'GET',
                success: function (data) {
                    logicDataList.updateStatusConnection(data);
                    reloadList();
                },
                error: function (request, status, error) {
                    logicDataList.updateStatusConnection('error');
                    reloadList();
                }
            });
        }
        else {
            element_select.attr('ready', 'true');
            reloadList();
        }
    }

}