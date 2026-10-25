// Copyright (c) 2026 AllIsA1. SPDX-License-Identifier: MIT
(function () {
  'use strict';
  var TEXT = {
    en: {
      title: 'CSQTT members',
      intro: 'Every client of the CSQTT inbound gets a member with a password of its own on the CSQTT server, and their subscription carries their own link instead of the shared one, so several people can use CSQTT at the same time. A client that is switched off, expired or out of traffic is switched off on the server too. A client taken off the inbound loses the member.',
      colClient: 'Client', colState: 'State', colOn: 'On', colSessions: 'Sessions',
      empty: 'No client is attached to the CSQTT inbound yet.',
      sync: 'Check now', yes: 'yes', no: 'no',
      states: { ok: 'ready', created: 'just created', off: 'off', taken: 'the name is taken by a member made by hand (its link is used)', failed: 'failed' },
      summary: function (s) { return 'Server: ' + s.server + ' · checked ' + new Date(s.checkedAt).toLocaleString(); },
      never: 'Not checked yet.',
    },
    ru: {
      title: 'Участники CSQTT',
      intro: 'Каждый клиент CSQTT-инбаунда получает на сервере CSQTT участника со своим паролем, а в подписке — свою ссылку вместо общей, так что CSQTT могут пользоваться несколько человек одновременно. Выключенный, просроченный клиент или без трафика отключается и на сервере. Клиент, снятый с инбаунда, теряет участника.',
      colClient: 'Клиент', colState: 'Состояние', colOn: 'Вкл', colSessions: 'Сессии',
      empty: 'К CSQTT-инбаунду пока не привязан ни один клиент.',
      sync: 'Проверить сейчас', yes: 'да', no: 'нет',
      states: { ok: 'готов', created: 'только что создан', off: 'выключен', taken: 'имя занято участником, созданным вручную (используется его ссылка)', failed: 'ошибка' },
      summary: function (s) { return 'Сервер: ' + s.server + ' · проверено ' + new Date(s.checkedAt).toLocaleString(); },
      never: 'Ещё не проверялось.',
    },
  };
  var lang = 'en';
  var last = null;
  function T() { return TEXT[lang] || TEXT.en; }
  function $(id) { return document.getElementById(id); }
  function cell(text) { var td = document.createElement('td'); td.textContent = text; return td; }
  function render(s) {
    last = s;
    var t = T();
    document.querySelectorAll('[data-i18n]').forEach(function (n) { var v = t[n.getAttribute('data-i18n')]; if (typeof v === 'string') n.textContent = v; });
    $('summary').textContent = s.checkedAt && s.checkedAt.indexOf('0001') !== 0 ? t.summary(s) : t.never;
    $('error').hidden = !s.error;
    $('error').textContent = s.error || '';
    var body = $('members').querySelector('tbody');
    body.textContent = '';
    (s.members || []).forEach(function (m) {
      var tr = document.createElement('tr');
      tr.appendChild(cell(m.email));
      tr.appendChild(cell(t.states[m.state] || m.state));
      tr.appendChild(cell(m.active ? t.yes : t.no));
      tr.appendChild(cell(String(m.sessions)));
      body.appendChild(tr);
    });
    $('empty').hidden = (s.members || []).length > 0;
  }
  function load() {
    return lucx.api('/api/status').then(function (res) { if (res.ok) render(res.body); });
  }
  $('sync').onclick = function () {
    lucx.api('/api/sync', { method: 'POST', body: {} }).then(function () { window.setTimeout(load, 2500); });
  };
  function setLang(ctx) {
    lang = ctx && ctx.lang && String(ctx.lang).slice(0, 2) === 'ru' ? 'ru' : 'en';
    lucx.applyTheme();
    if (last) render(last); else render({ members: [] });
  }
  lucx.ready().then(function (ctx) { setLang(ctx); load(); window.setInterval(load, 10000); });
  lucx.onContext(setLang);
})();
