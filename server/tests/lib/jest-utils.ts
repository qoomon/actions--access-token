import {DIM_COLOR} from 'jest-matcher-utils'
import {JestAssertionError} from 'expect'

/**
 * Wrap test with hints
 * @param test - test function
 * @param hints - hint messages
 * @returns void
 */
export function withHint(test: () => void, hints: Record<string, string>) {
  try {
    test()
  } catch (e: any) {
    if (e instanceof JestAssertionError || 'matcherResult' in e) {
      const hintMessage = 'Hints:\n' + indent(
          Object.entries(hints).map(([name, message]) => {
            const formattedMessage = message.includes('\n') ?
                `\n${indent(message)}` :
                ` ${message}`
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
 * @returns indented string
 */
function indent(string: string, indent: string = '  ') {
  return string.split('\n')
      .map((line) => `${indent}${line}`)
      .join('\n')
}
