/* SPDX-License-Identifier: GPL-2.0-or-later */

/* The status page loads every file in this directory, which is the only way to
 * add a row here: procd's `system board` has no serial and LuCI's own System
 * table is a fixed list. Renders nothing where the factory data is absent, so
 * it is harmless on boards that do not publish any. */

'use strict';
'require baseclass';
'require rpc';

const callBoard = rpc.declare({
	object: 'luci.poe',
	method: 'getBoard',
	expect: { }
});

return baseclass.extend({
	title: _('Board'),

	load() {
		return L.resolveDefault(callBoard(), {});
	},

	render(board) {
		const fields = [
			_('Product'),          board.product,
			_('Serial Number'),    board.serial,
			_('Hardware Version'), board.hwver
		];

		const table = E('table', { 'class': 'table' });

		for (let i = 0; i < fields.length; i += 2) {
			if (!fields[i + 1])
				continue;

			table.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '33%' }, [ fields[i] ]),
				E('td', { 'class': 'td left' }, [ fields[i + 1] ])
			]));
		}

		return table.childNodes.length ? table : E([]);
	}
});
