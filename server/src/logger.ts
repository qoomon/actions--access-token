import pino from "pino";
import asyncHooks from "node:async_hooks";
import process from "process";
import {v4 as uuid} from "uuid";

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
  mixin: () => asyncBindings.getStore()?.bindings ?? {},
  hooks: {
    logMethod(inputArgs, method) {
      if (typeof inputArgs[0] === 'object' && typeof inputArgs[1] === 'string') {
        // --- arrange message field to be first
        // @ts-expect-error inputArgs[0] will be an object
        inputArgs[0] = {
          // @ts-expect-error field needs be defined at first to set position
          [_loggerMessageKey]: undefined, // move message to first position
          ...(inputArgs[0] as object), // apply other properties
          ...{[_loggerMessageKey]: inputArgs[1]} // always overwrite messageKey with message
        };
        if (inputArgs.length <= 2) inputArgs.pop();
        else inputArgs[1] = undefined;
      }

      return method.apply(this, inputArgs);
    }
  },
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

  const bindingsId = uuid();
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
  return fn().finally(() => deleteAsyncBindings(asyncLoggerBindingsId));
}

function buildBindings(bindingsSources: Map<string, Bindings>) {
  return [...bindingsSources.values()]
      .reduce((acc, val) => ({...acc, ...val}), {});
}
