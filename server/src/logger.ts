import pino from "pino";
import asyncHooks from "node:async_hooks";
import process from "process";
import { v4 as uuid } from "uuid";

type Bindings = Record<string, unknown>;
const asyncBindings = new asyncHooks.AsyncLocalStorage<{
  bindingsSources: Map<string, Bindings>,
  bindings: Bindings,
}>();

export const logger = pino({
  level: process.env.LOG_LEVEL?.toLowerCase() || "info",
  formatters: {
    level: (label) => ({ level: label.toUpperCase() }),
  },
  mixin: () => asyncBindings.getStore()?.bindings ?? {},
});

export function setAsyncLoggerBindings(bindings : Bindings) {
  const store = asyncBindings.getStore() ?? {
    bindingsSources: new Map(),
    bindings: {},
  };

  const bindingsId = uuid();
  store.bindingsSources.set(bindingsId, bindings);
  store.bindings = buildBindings(store.bindingsSources);

  asyncBindings.enterWith(store);

  return bindingsId;
}

export function deleteAsyncLoggerBindings(id: string) {
  const store = asyncBindings.getStore();
  if (!store || !store.bindingsSources.has(id)) throw new Error("Unkown async logger bindings id");
  store.bindingsSources.delete(id);
  store.bindings = buildBindings(store.bindingsSources);
}

function buildBindings(bindingsSources: Map<string, Bindings>){
  return [...bindingsSources.values()]
    .reduce((acc, val) => ({ ...acc, ...val }),{});
}
