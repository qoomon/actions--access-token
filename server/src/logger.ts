import pino from "pino";
import asyncHooks from "node:async_hooks";
import process from "process";

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
  withAsyncBindings,
};

export const logger: typeof _logger & typeof _loggerExtensions = Object.assign(_logger, _loggerExtensions);

async function withAsyncBindings<T>(bindings: Bindings, fn: () => Promise<T>): Promise<T> {
  const current = asyncBindings.getStore();
  const baseBindings = current?.bindings ?? {};
  const store = {
    bindingsSources: new Map<string, Bindings>(),
    bindings: {...baseBindings, ...bindings},
  };

  return asyncBindings.run(store, fn);
}
