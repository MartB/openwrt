/* SPDX-License-Identifier: GPL-2.0-or-later */

'use strict';
'require view';
'require rpc';
'require dom';
'require ui';

const callStatus = rpc.declare({
	object: 'luci.poe',
	method: 'getStatus',
	expect: { }
});

const callCableTest = rpc.declare({
	object: 'luci.poe',
	method: 'cableTest',
	params: [ 'port' ],
	expect: { }
});

/* Anything but OK is worth showing in red, except on a port with nothing
 * plugged in, where an open pair is the expected reading rather than a fault. */
function codeColour(code, carrier) {
	if (code == 'OK')
		return '#3aa03a';
	if (!carrier && code == 'Open Circuit')
		return '#888';

	return '#c00';
}

return view.extend({
	load() {
		return callStatus();
	},

	renderResult(res, carrier) {
		if (!res)
			return E('span', { 'style': 'color:#888' }, '—');

		if (!res.success)
			return E('span', { 'style': 'color:#c00' }, res.error || _('failed'));

		return E('span', {}, (res.pairs || []).map(function(p, i) {
			return E('span', { 'style': 'margin-right:1.5em' }, [
				E('span', { 'style': 'color:#666' }, p.pair.replace('Pair ', '') + ': '),
				E('strong', { 'style': 'color:%s'.format(codeColour(p.code, carrier)) },
				  p.code || '?'),
				/* The PHY subtracts a fixed 620 from its raw reading and clamps
				 * at zero, so 0 means the fault is at the connector rather than
				 * unmeasured -- which is what an empty port looks like. */
				(p.code && p.code != 'OK')
					? E('span', { 'style': 'color:#666' },
					    p.metres > 0 ? ' %.1f m'.format(p.metres) : ' ' + _('at port'))
					: ''
			]);
		}));
	},

	handleTest(port, carrier, cell, btn) {
		if (carrier && !confirm(_('Testing %s drops the link while the PHY measures the cable. Continue?').format(port)))
			return Promise.resolve();

		dom.content(cell, E('em', {}, _('testing…')));
		btn.disabled = true;

		return callCableTest(port).then(L.bind(function(res) {
			dom.content(cell, this.renderResult(res, carrier));
			btn.disabled = false;
		}, this)).catch(function(e) {
			dom.content(cell, E('span', { 'style': 'color:#c00' }, '' + e));
			btn.disabled = false;
		});
	},

	renderPorts(st) {
		const self = this;
		const rows = st.ports.map(function(p) {
			const cell = E('div', { 'class': 'td' },
				E('span', { 'style': 'color:#888' }, '—'));
			const btn = E('button', { 'class': 'cbi-button cbi-button-action' },
				_('Test'));

			btn.addEventListener('click', ui.createHandlerFn(self, function() {
				return self.handleTest(p.port, p.carrier, cell, btn);
			}));

			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td' }, [
					E('strong', {}, p.port),
					p.label ? E('div', { 'style': 'color:#666;font-size:90%' }, p.label) : ''
				]),
				E('div', { 'class': 'td' }, p.carrier ? _('up') : _('down')),
				cell,
				E('div', { 'class': 'td' }, btn)
			]);
		});

		if (!rows.length)
			rows.push(E('div', { 'class': 'tr placeholder' },
				E('div', { 'class': 'td' }, E('em', {}, _('No ports found.')))));

		return E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th' }, _('Port')),
				E('div', { 'class': 'th' }, _('Link')),
				E('div', { 'class': 'th' }, _('Result')),
				E('div', { 'class': 'th' }, _('Action'))
			])
		].concat(rows));
	},

	render(st) {
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Cable diagnostics')),
			E('p', { 'class': 'cbi-section-descr' },
			  _('Time-domain reflectometry on each of the four pairs, run by the PHY \
itself. A port with nothing plugged in reads as open at the port, which is normal. \
Distance is measured from a fixed offset the PHY subtracts, so a fault nearer \
than that reads as at the port rather than as a distance. Testing a port that \
is up briefly drops its link.')),
			this.renderPorts(st)
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
