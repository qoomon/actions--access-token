import {DIM_COLOR} from 'jest-matcher-utils';

/**
 * Wrap test with hints
 * @param test - test function
 * @param hints - hint messages
 * @return void
 */
export async function withHint(
    test: () => void | Promise<void>,
    hints: () => Record<string, unknown> | Promise<Record<string, unknown>>,
) {
  try {
    await test();
  } catch (e: unknown) {
    if (e instanceof Error && e.constructor.name === 'JestAssertionError') {
      console.log(e.constructor.name);
      const hintMessage = `Hints:\n${indent(
          Object.entries(await hints()).map(([name, message]) => {
            let formattedMessage;
            if (typeof message === 'string') {
              formattedMessage = message.includes('\n') ?
                  `\n${indent(message)}` :
                  ` ${message}`;
            } else {
              formattedMessage = JSON.stringify(message, null, 2);
            }
            return DIM_COLOR(`${name}:${formattedMessage}`);
          }).join('\n'),
      )}`;
      e.message = `${e.message}\n${hintMessage}`;
    }

    throw e;
  }
}

/**
 * Indent string
 * @param string - string to indent
 * @param indention - indention string
 * @return indented string
 */
function indent(string: string, indention = '  ') {
  return string.split('\n')
      .map((line) => `${indention}${line}`)
      .join('\n');
}
