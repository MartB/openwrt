/* SPDX-License-Identifier: GPL-2.0-or-later */

'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require ui';

const callStatus = rpc.declare({
	object: 'luci.poe',
	method: 'getStatus',
	expect: { }
});

const callSetEee = rpc.declare({
	object: 'luci.poe',
	method: 'setEee',
	params: [ 'port', 'enable' ],
	expect: { }
});

const callSetAldps = rpc.declare({
	object: 'luci.poe',
	method: 'setAldps',
	params: [ 'port', 'enable' ],
	expect: { }
});

function toggle(self, value, handler) {
	if (value == null)
		return E('span', { 'style': 'color:#888' }, '—');

	return E('input', {
		'type': 'checkbox',
		'checked': value ? '' : null,
		'change': ui.createHandlerFn(self, function(ev) {
			return handler(ev.target.checked).then(() => self.refresh());
		})
	});
}

return view.extend({
	load() {
		return callStatus();
	},

	renderPorts(st) {
		const self = this;
		const rows = st.ports.map(function(p) {
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td' }, [
					E('strong', {}, p.port),
					p.label ? E('div', { 'style': 'color:#666;font-size:90%' }, p.label) : ''
				]),
				E('div', { 'class': 'td' }, p.carrier ? _('up') : _('down')),
				E('div', { 'class': 'td' }, toggle(self, p.eee,
					(v) => callSetEee(p.port, v))),
				E('div', { 'class': 'td' }, toggle(self, p.aldps,
					(v) => callSetAldps(p.port, v)))
			]);
		});

		if (!rows.length)
			rows.push(E('div', { 'class': 'tr placeholder' },
				E('div', { 'class': 'td' }, E('em', {}, _('No ports found.')))));

		return E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th' }, _('Port')),
				E('div', { 'class': 'th' }, _('Link')),
				E('div', { 'class': 'th' }, _('EEE')),
				E('div', { 'class': 'th' }, _('ALDPS'))
			])
		].concat(rows));
	},

	refresh() {
		return callStatus().then(L.bind(function(st) {
			dom.content(this.container, this.renderAll(st));
		}, this));
	},

	renderAll(st) {
		return [
			E('div', { 'class': 'cbi-section' }, [
				E('h3', _('Energy Efficient Ethernet')),
				E('p', { 'class': 'cbi-section-descr' },
				  _('EEE (802.3az) idles the PHY between frames on a live link and \
needs the link partner to agree, so a port can be enabled here and still report \
off. ALDPS powers the PHY down while the link is down, so it only does anything \
on a port with nothing plugged in. A dash means the port has no such control.')),
				this.renderPorts(st)
			])
		];
	},

	render(st) {
		this.container = E('div', {}, this.renderAll(st));
		poll.add(L.bind(this.refresh, this), 15);

		return this.container;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
