/** Returns the path of every `undefined` value, including inside arrays. */
export function findUndefined(value: unknown, path = "$"): string[] {
  if (value === undefined) return [path];
  if (Array.isArray(value)) {
    return value.flatMap((item, i) => findUndefined(item, `${path}[${i}]`));
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, item]) =>
      findUndefined(item, `${path}.${key}`),
    );
  }
  return [];
}

/** Recursively freezes an object graph so any in-place mutation throws in strict mode. */
export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.values(value as Record<string, unknown>).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}
