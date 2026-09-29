/*!
Mapping between the Policy page's dropdowns and a strategy's options.
*/

/** Dropdown value for a setting absent from the policy. */
export const NOT_MANAGED = '__not_managed__';

export function choicesFromOptions(keys: string[], options: Record<string, string>): Record<string, string> {
    return Object.fromEntries(keys.map((k) => [k, k in options ? options[k] : NOT_MANAGED]));
}

export function optionsFromChoices(choices: Record<string, string>): Record<string, string> {
    return Object.fromEntries(Object.entries(choices).filter(([, v]) => v !== NOT_MANAGED));
}

const VALUE_LABELS: Record<string, string> = {
    Y: 'Allowed',
    N: 'Denied',
    custom: 'Custom',
    full: 'Full access',
    view: 'Screen share only',
};

export function valueLabel(value: string): string {
    return VALUE_LABELS[value] ?? value;
}
