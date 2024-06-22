import {DIM_COLOR} from 'jest-matcher-utils'
import {JestAssertionError} from 'expect'

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
    await test()
  } catch (e: unknown) {
    if (e instanceof JestAssertionError) {
      const hintMessage = 'Hints:\n' + indent(
          Object.entries(await hints()).map(([name, message]) => {
            let formattedMessage = ''
            if (typeof message === 'string') {
              formattedMessage = message.includes('\n') ?
                  `\n${indent(message)}` :
                  ` ${message}`
            } else {
              formattedMessage = JSON.stringify(message, null, 2)
            }
            // eslint-disable-next-line new-cap
            return DIM_COLOR(`${name}:${formattedMessage}`)
          }).join('\n'),
      )
      e.message = e.message + '\n' + hintMessage
    }

    throw e
  }
}

/**
 * Indent string
 * @param string - string to indent
 * @param indent - indent string
 * @return indented string
 */
function indent(string: string, indent = '  ') {
  return string.split('\n')
      .map((line) => `${indent}${line}`)
      .join('\n')
}
