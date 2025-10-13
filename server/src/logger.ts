import pino from "pino";
import asyncHooks from "node:async_hooks";
import process from "process";
import * as crypto from 'node:crypto';

type Bindings = Record<string, unknown>;
const asyncBindings = new asyncHooks.AsyncLocalStorage<{
  bindingsSources: Map<string, Bindings>,
  bindings: Bindings,
}>();

const _loggerMessageKey = "msg";
const _logger = pino({
  level: process.env.LOG_LEVEL?.toLowerCase() || "info",
  messageKey: _loggerMessageKey,
  base: {},
  formatters: {
    level: (label) => ({level: label.toUpperCase()}),
  },
  mixin: () => ({...asyncBindings.getStore()?.bindings}),
});

const _loggerExtensions = {
  setAsyncBindings,
  deleteAsyncBindings,
  withAsyncBindings,
};

export const logger: typeof _logger & typeof _loggerExtensions = Object.assign(_logger, _loggerExtensions);

function setAsyncBindings(bindings: Bindings) {
  const store = asyncBindings.getStore() ?? {
    bindingsSources: new Map(),
    bindings: {},
  };

  const bindingsId = crypto.randomUUID();
  store.bindingsSources.set(bindingsId, bindings);
  store.bindings = buildBindings(store.bindingsSources);

  asyncBindings.enterWith(store);
  return bindingsId;
}

function deleteAsyncBindings(id: string) {
  const store = asyncBindings.getStore();
  if (!store || !store.bindingsSources.has(id)) throw new Error("Unknown async logger bindings id");
  store.bindingsSources.delete(id);
  store.bindings = buildBindings(store.bindingsSources);
}

async function withAsyncBindings<T>(bindings: Bindings, fn: () => Promise<T>): Promise<T> {
  const asyncLoggerBindingsId = setAsyncBindings(bindings);
  return fn()
      .finally(() => deleteAsyncBindings(asyncLoggerBindingsId));
}

function buildBindings(bindingsSources: Map<string, Bindings>) {
  return [...bindingsSources.values()]
      .reduce((acc, val) => ({...acc, ...val}), {});
}
