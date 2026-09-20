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

const callSetPoe = rpc.declare({
	object: 'luci.poe',
	method: 'setPoe',
	params: [ 'port', 'enable' ],
	expect: { }
});

const callSetLimit = rpc.declare({
	object: 'luci.poe',
	method: 'setLimit',
	params: [ 'port', 'limit_mw' ],
	expect: { }
});

const callSetPriority = rpc.declare({
	object: 'luci.poe',
	method: 'setPriority',
	params: [ 'port', 'priority' ],
	expect: { }
});

const callSetLegacy = rpc.declare({
	object: 'luci.poe',
	method: 'setLegacy',
	params: [ 'port', 'enable' ],
	expect: { }
});

/* 802.3 class -> the standard the PD negotiated, and the colour the front
 * panel uses for it in PoE display mode. */
function classInfo(cls) {
	if (cls == null)
		return { name: '-', colour: null };
	if (cls <= 3)
		return { name: '802.3af', colour: '#d8b400' };
	if (cls == 4)
		return { name: '802.3at', colour: '#3aa03a' };
	return { name: '802.3bt', colour: '#2a7fd4' };
}

function mW(v) {
	if (v == null)
		return '-';
	return '%.1f W'.format(v / 1000);
}

function statusBadge(p) {
	const s = (p.status || '').toLowerCase();
	let text = p.status || '-', colour = '#888';

	if (s.indexOf('delivering') >= 0)      { text = _('delivering'); colour = '#3aa03a'; }
	else if (s.indexOf('fault') >= 0)      { text = _('fault');      colour = '#c00'; }
	else if (s.indexOf('searching') >= 0)  { text = _('searching');  colour = '#d8b400'; }
	else if (p.admin == 'disabled')        { text = _('disabled');   colour = '#888'; }

	return E('span', {
		'style': 'color:%s;font-weight:bold'.format(colour)
	}, text);
}

return view.extend({
	load() {
		return callStatus();
	},

	renderSummary(st) {
		const usedPct = st.budget_mw > 0 ? (st.used_mw * 100 / st.budget_mw) : 0;

		/* Mirrors the indicator on the front panel: green with >=20% of the
		 * budget free, amber 5-20%, red below 5% or on a fault. */
		let colour = '#3aa03a';
		if (st.faults > 0 || st.free_pct < 5)
			colour = '#c00';
		else if (st.free_pct < 20)
			colour = '#d8b400';

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Power budget')),
			E('div', {
				'style': 'border:1px solid #ccc;border-radius:3px;height:1.4em;' +
				         'width:100%;max-width:40em;overflow:hidden;background:#f5f5f5'
			}, E('div', {
				'style': 'background:%s;height:100%%;width:%.1f%%'.format(colour, Math.min(usedPct, 100))
			}, ' ')),
			E('p', {}, [
				/* Both figures measured, so no total is quoted; without them
				 * the configured budget is all there is. */
				st.free_mw != null
					? _('%s drawn — %s available').format(mW(st.used_mw), mW(st.free_mw))
					: _('%s of %s drawn').format(mW(st.used_mw), mW(st.budget_mw)),
				' — ',
				_('%.0f%% free').format(st.free_pct),
				st.allocated_mw ? E('span', { 'style': 'color:#666' },
					' — ' + _('%s allocated by class').format(mW(st.allocated_mw))) : '',
				st.free_mw == null ? E('span', { 'style': 'color:#666' },
					' — ' + (st.budget_source == 'configured'
						? _('budget from configuration')
						: _('budget assumed'))) : '',
				st.faults > 0 ? E('strong', { 'style': 'color:#c00' },
					' — ' + _('%d port(s) in fault').format(st.faults)) : ''
			])
		]);
	},

	/* Read-only here: a status page reports, it does not configure. The
	 * mode lives in Settings, and on the front-panel LED-mode button. */
	renderLedMode(st) {
		if (!st.has_led_mode)
			return E([]);

		const names = {
			speed: _('Link speed'),
			poe:   _('PoE class'),
			off:   _('Off')
		};

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Front panel LED mode')),
			E('p', {}, [
				E('strong', {}, names[st.led_mode] || st.led_mode),
				' \u2014 ',
				E('a', { 'href': L.url('admin/services/poe/settings') }, _('Settings'))
			])
		]);
	},

	/* The SoC's critical trip is 105 C, so 85 is the first number worth
	 * looking at twice. */
	renderTemps(st) {
		if (!st.temps || !st.temps.length)
			return E([]);

		const cells = st.temps.map(function(t) {
			const c = t.mc / 1000;
			const colour = c >= 85 ? '#c00' : (c >= 70 ? '#d8b400' : '#3aa03a');
			const name = t.label || t.chip;

			return E('div', { 'style': 'display:inline-block;margin-right:2em' }, [
				E('span', { 'style': 'color:#666' }, name + ': '),
				E('strong', { 'style': 'color:%s'.format(colour) },
				  '%.1f °C'.format(c))
			]);
		});

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Temperatures')),
			E('p', {}, cells)
		]);
	},

	/* Zero rpm is only news if the board says it should be turning. */
	renderFans(st) {
		if (!st.fans || !st.fans.length)
			return E([]);

		const cells = st.fans.map(function(f) {
			const bad = (f.fault === true || f.alarm === true);

			return E('div', { 'style': 'display:inline-block;margin-right:2em' }, [
				E('span', { 'style': 'color:#666' }, _('Fan') + ': '),
				E('strong', { 'style': 'color:%s'.format(bad ? '#c00' : '#3aa03a') },
				  '%d rpm'.format(f.rpm)),
				bad ? E('strong', { 'style': 'color:#c00' }, ' \u2014 ' + _('stopped')) : ''
			]);
		});

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Fans')),
			E('p', {}, cells)
		]);
	},

	renderPorts(st) {
		const self = this;
		const rows = [];

		for (let i = 0; i < st.ports.length; i++) {
			const p = st.ports[i];
			const ci = classInfo(p.class);
			const on = (p.admin == 'enabled');

			rows.push(E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td' }, [
					E('strong', {}, p.port),
					p.label ? E('div', { 'style': 'color:#666;font-size:90%' }, p.label) : ''
				]),
				E('div', { 'class': 'td' }, p.carrier ? _('up') : _('down')),
				E('div', { 'class': 'td' }, statusBadge(p)),
				E('div', { 'class': 'td' }, ci.colour
					? E('span', { 'style': 'color:%s'.format(ci.colour) }, ci.name)
					: ci.name),
				E('div', { 'class': 'td' }, mW(p.power_mw)),
				E('div', { 'class': 'td' }, E('input', {
					'type': 'number', 'min': 1, 'max': 100, 'step': 0.1,
					'style': 'width:5em',
					'value': p.limit_mw != null ? (p.limit_mw / 1000) : '',
					'change': ui.createHandlerFn(this, function(ev) {
						const w = parseFloat(ev.target.value);
						if (!(w > 0))
							return self.refresh();
						return callSetLimit(p.port, Math.round(w * 1000))
							.then(() => self.refresh());
					})
				})),
				E('div', { 'class': 'td' }, E('input', {
					'type': 'number', 'min': 0,
					'max': p.prio_max != null ? p.prio_max : 15,
					'step': 1, 'style': 'width:4em',
					'value': p.priority != null ? p.priority : '',
					'change': ui.createHandlerFn(this, function(ev) {
						const v = parseInt(ev.target.value, 10);
						if (isNaN(v))
							return self.refresh();
						return callSetPriority(p.port, v).then(() => self.refresh());
					})
				})),
				E('div', { 'class': 'td' }, p.legacy == null
					? E('span', { 'style': 'color:#888' }, '\u2014')
					: E('input', {
						'type': 'checkbox',
						'checked': p.legacy ? '' : null,
						'change': ui.createHandlerFn(this, function(ev) {
							return callSetLegacy(p.port, ev.target.checked)
								.then(() => self.refresh());
						})
					})),
				E('div', { 'class': 'td' }, E('button', {
					'class': 'cbi-button ' + (on ? 'cbi-button-reset' : 'cbi-button-add'),
					'click': ui.createHandlerFn(this, function() {
						return callSetPoe(p.port, !on).then(() => self.refresh());
					})
				}, on ? _('Disable') : _('Enable')))
			]));
		}

		if (!rows.length)
			rows.push(E('div', { 'class': 'tr placeholder' },
				E('div', { 'class': 'td' }, E('em', {}, _('No PoE-capable ports found.')))));

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', _('Ports')),
			E('div', { 'class': 'table' }, [
				E('div', { 'class': 'tr table-titles' }, [
					E('div', { 'class': 'th' }, _('Port')),
					E('div', { 'class': 'th' }, _('Link')),
					E('div', { 'class': 'th' }, _('PoE')),
					E('div', { 'class': 'th' }, _('Standard')),
					E('div', { 'class': 'th' }, _('Draw')),
					E('div', { 'class': 'th' }, _('Limit (W)')),
					E('div', { 'class': 'th' }, _('Priority')),
					E('div', { 'class': 'th', 'title':
						_('Widen PD detection to accept pre-802.3af devices') },
					  _('Legacy')),
					E('div', { 'class': 'th' }, _('Action'))
				])
			].concat(rows))
		]);
	},

	refresh() {
		return callStatus().then(L.bind(function(st) {
			const fresh = this.renderAll(st);
			dom.content(this.container, fresh);
		}, this));
	},

	renderAll(st) {
		return [
			this.renderSummary(st),
			this.renderTemps(st),
			this.renderFans(st),
			this.renderLedMode(st),
			this.renderPorts(st)
		];
	},

	render(st) {
		this.container = E('div', {}, this.renderAll(st));

		/* Each refresh is one ethtool call per port, and every one of those is
		 * several round trips over a 115200 baud link to the PSE MCU. Poll
		 * slowly; PoE state only changes when someone plugs something in. */
		poll.add(L.bind(this.refresh, this), 15);

		return this.container;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
