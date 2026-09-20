/* SPDX-License-Identifier: GPL-2.0-or-later */

'use strict';
'require view';
'require form';
'require rpc';
'require uci';

const callSetLedMode = rpc.declare({
	object: 'luci.poe',
	method: 'setLedMode',
	params: [ 'mode' ],
	expect: { }
});

return view.extend({
	load() {
		return uci.load('poe-led');
	},

	render() {
		const m = new form.Map('poe-led', _('PoE LEDs'));

		const s = m.section(form.NamedSection, 'main', 'poe-led');
		s.anonymous = true;

		let o;

		o = s.option(form.ListValue, 'mode', _('LED mode'),
			_('What the port LEDs show. Also cycled by the front-panel button.'));
		o.value('speed', _('Link speed'));
		o.value('poe',   _('PoE class'));
		o.value('off',   _('Off'));
		o.default = 'speed';

		o = s.option(form.ListValue, 'indicator', _('PoE indicator'),
			_('Gauge: green above 20% of the budget free, amber 5-20%, red below 5%. A faulted port always shows red.'));
		o.value('gauge',  _('Budget gauge'));
		o.value('active', _('Green when any port is delivering'));
		o.value('off',    _('Never lit'));
		o.default = 'gauge';

		/* Entered in watts because nobody thinks in milliwatts; stored in
		 * mW because that is the unit the PSE driver reports power in. */
		o = s.option(form.Value, 'budget_mw', _('PoE budget (W)'),
			_('Only used if the hardware does not report its own budget.'));
		o.datatype = 'and(ufloat,min(1))';
		o.placeholder = '130';

		o.cfgvalue = function(section_id) {
			const mw = uci.get('poe-led', section_id, 'budget_mw');
			return (mw != null && mw !== '') ? String(+mw / 1000) : '';
		};

		o.write = function(section_id, value) {
			uci.set('poe-led', section_id, 'budget_mw',
			        String(Math.round(parseFloat(value) * 1000)));
		};

		o.remove = function(section_id) {
			uci.unset('poe-led', section_id, 'budget_mw');
		};

		o = s.option(form.Flag, 'alert_when_off', _('Show faults in Off mode'),
			_('Red still lights on a fault or exhausted budget.'));
		o.default = '1';
		o.depends('mode', 'off');

		o = s.option(form.Flag, 'keep_power', _('Keep power LED lit'));
		o.default = '0';
		o.depends('mode', 'off');

		return m.render();
	},

	/* The daemon caches these, so repaint after applying. */
	handleSaveApply(ev, mode) {
		return this.super('handleSaveApply', [ ev, mode ]).then(function() {
			return callSetLedMode(uci.get('poe-led', 'main', 'mode') || 'speed');
		});
	}
});
