import {expect} from '@jest/globals';
import type {MatcherContext} from 'expect';

export interface ResponseExpectation {
  status: number;
  body?: Record<string, unknown>;
}

declare module '@jest/globals' {
  // noinspection JSUnusedGlobalSymbols
  interface Matchers<R> {
    toMatchResponse(expected: ResponseExpectation): Promise<R>;
  }
}

expect.extend({
  /**
   * Assert that a Response has the expected HTTP status and, optionally, that
   * its JSON body matches a subset of the expected object.  On failure the
   * full parsed body is always included in the error message, so there is no
   * need to fetch and print it separately in tests.
   */
  async toMatchResponse(this: MatcherContext, received: Response, expected: ResponseExpectation) {
    const body = await received.json().catch(() => null);

    if (received.status !== expected.status) {
      return {
        pass: false,
        message: () => [
          this.utils.matcherHint('toMatchResponse', 'response', ''),
          '',
          `Expected status: ${this.utils.printExpected(expected.status)}`,
          `Received status: ${this.utils.printReceived(received.status)}`,
          '',
          `Response body:\n${JSON.stringify(body, null, 2)}`,
        ].join('\n'),
      };
    }

    if (expected.body !== undefined) {
      const pass = this.equals(body, expected.body, [
        this.utils.iterableEquality,
        this.utils.subsetEquality,
      ]);
      if (!pass) {
        return {
          pass: false,
          message: () => [
            this.utils.matcherHint('toMatchResponse', 'response', ''),
            '',
            this.utils.diff(expected.body, body) ?? '',
          ].join('\n'),
        };
      }
    }

    return {
      pass: true,
      message: () => this.utils.matcherHint('.not.toMatchResponse', 'response', ''),
    };
  },
});
