export function listFieldValue(value: string[] | number[] | string | undefined) {
  if (Array.isArray(value)) return value.join(', ');
  return value || '';
}
