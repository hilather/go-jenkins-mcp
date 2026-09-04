import { beforeEach } from "vitest";

/**
 * Node 25+ experimental global localStorage is undefined without
 * --localstorage-file and shadows jsdom's window.localStorage.
 */

function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null;
    },
    key(index: number) {
      return [...map.keys()][index] ?? null;
    },
    removeItem(key: string) {
      map.delete(key);
    },
    setItem(key: string, value: string) {
      map.set(String(key), String(value));
    },
  };
}

const store = memoryStorage();

Object.defineProperty(globalThis, "localStorage", {
  configurable: true,
  writable: true,
  enumerable: true,
  value: store,
});

if (typeof window !== "undefined") {
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    writable: true,
    enumerable: true,
    value: store,
  });
}

beforeEach(() => {
  store.clear();
});
