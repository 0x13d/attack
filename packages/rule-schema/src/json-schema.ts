import { OPS, SCOPES } from './types';

/**
 * Build the JSON Schema for an authored rule **from the canonical TS source** (ADR-004). The op + scope enums
 * come from `OPS`/`SCOPES`; the response-id enum is passed in by the caller (the engine derives it from the
 * live response registry) so this stays engine-free. A generator script writes the result to the VSCode
 * extension's `schemas/`, and a drift check fails the build if the committed file is stale.
 */
export function buildRuleJsonSchema(responseIds: readonly string[]): Record<string, unknown> {
  const condition = {
    oneOf: [
      { type: 'object', additionalProperties: false, required: ['all'], properties: { all: { type: 'array', minItems: 1, items: { $ref: '#/definitions/condition' } } } },
      { type: 'object', additionalProperties: false, required: ['any'], properties: { any: { type: 'array', minItems: 1, items: { $ref: '#/definitions/condition' } } } },
      { type: 'object', additionalProperties: false, required: ['not'], properties: { not: { $ref: '#/definitions/condition' } } },
      {
        type: 'object',
        additionalProperties: false,
        required: ['field', 'op'],
        properties: {
          field: { type: 'string', description: 'Dot-path over the signal view, e.g. payload.installType.' },
          op: { enum: [...OPS] },
          value: {},
        },
      },
    ],
  };

  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: '0x13d::att&ck rule',
    description:
      'GENERATED from @attack/rule-schema (ADR-004) — do not edit by hand; run `npm run gen:schema`. A ' +
      'declarative detection rule (ADR-002): the engine interprets the condition as data, never code.',
    type: 'object',
    additionalProperties: false,
    required: ['id', 'name', 'technique', 'scope', 'condition', 'responses'],
    properties: {
      id: { type: 'string', minLength: 1 },
      name: { type: 'string', minLength: 1 },
      technique: { type: 'string', description: 'MITRE ATT&CK technique id, e.g. T1176.001.' },
      scope: { enum: [...SCOPES] },
      enabled: { type: 'boolean' },
      responses: {
        type: 'array',
        minItems: 1,
        items: { enum: [...responseIds] },
        description: 'Response ids resolved against the engine response registry — never code.',
      },
      condition: { $ref: '#/definitions/condition' },
    },
    definitions: { condition },
  };
}
