'use strict';

const { scan } = require('./scanner');
const { loadRuleset, listBuiltinRulesets } = require('./rules');
const { formatJson, formatText } = require('./formatter');

module.exports = { scan, loadRuleset, listBuiltinRulesets, formatJson, formatText };
