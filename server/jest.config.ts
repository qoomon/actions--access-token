import type {JestConfigWithTsJest} from 'ts-jest';

// Set up environment variables required by config.ts before modules are loaded
// These values are from test/fixtures.ts
process.env.GITHUB_APP_ID = '1234567890';
process.env.GITHUB_APP_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEApgH2MYIDYbfSFiLJWI5+qhslsWJSx/PI1RTzkNwBZT/FTJV4\n' +
    '8s+bjwzBsfWYNRegT2bWzDzeNMtRqZpLkaHF00eET3GU88twsO2gy8iDfWqqgre+\n' +
    '6D4tZ88hNGoKdm1pyp/FEJ8GhNyW2lIhoNmiVMy31JJFciyAf1lLERi35zw0XHD7\n' +
    'uTqN9S7QivrgHwlGNiSlqML2W9f4PbHvdHEyphRFHSyGMLQyKRX7dk7ndtAUTrxe\n' +
    'txDMZqDNB7hoQzVxTR41eDoglWN4Enb1NU7UF4C9j0EIOL/HjhKhfCiGnTXaTiMd\n' +
    'U4agocoArztK/k3HKlwHH4msw2bZT9m5bb4OfwIDAQABAoIBAQCUvCE2jkQ1YxsJ\n' +
    '1jUL8O+vvQ7ydSOyHswLjfAEE/n0G0TMrwdklXnMmyNYLLEosHhja8J7zvVP2/LY\n' +
    'wHOAka7K88Kp4xwPqnDXNLDipE6bKdyHrdWQA1VvMvePHIsvPCyS7L8Fe1W96F4I\n' +
    'UZnrodJ9o8X44OzztMeUUg6dzMXImIPvoVe9ctFBT3UCohXXCTj6jimiRXkvhahh\n' +
    'pq1jj1aJTCAsYRrd8Zl0o7hyqDTC/xzi7/TplV3a4Z4sqgj6f0GU2FU0+PcAlXj8\n' +
    'UAP+oCnVD1Rm7eaWMxLVD/4H4NvHFb2tNvDkwH5eRsQXCuHUHzcl/NjXRiopfAe+\n' +
    'tBrLEDSxAoGBAPL/Pbct4dGpt5KxT78dsuMPpYCFTBns61a8NdBUCM9t1DhWpfMz\n' +
    'VwiVNlFUiMYONi43ef8IUIo/fx8DwVp2CbEtdj1j8vC7+gAvTHcGI7SrOqutOooJ\n' +
    'omKsmcUkj3N9MX6i6j9ajnnAcQpxg8lLjccYQ8thpFdon9gJOcaFweQVAoGBAK7k\n' +
    'D7hzeoDuT4xjQD3RmftewnFEkWW2BUgfrkODO6fHjf0GjqJpAYEPjoPMeb2AnZiv\n' +
    'tbfFPN1TmGbcqipohN+lDLK56C2Draqgvn11LYKK4iCt1AjRNKvHkjisz6cHJFjd\n' +
    'nDoYzrPY7Zhmr6nz1DB+jLKx0s5/hWbZCXeqmClDAoGAMV9zJrkH3RXi2sd0MJzU\n' +
    'MBaJxidPYyUkXCc5t+6bK6phKGFSrquLz46hzryiXbudfp5/BzalRrHIHoEg1ESP\n' +
    'i5R1JdwdDJTlIwx5OOXic18nOKKl9k4m1G3FgK0BCLIzUEvB1MWNlWdokHqoEEpt\n' +
    'sDpZ7AUW4zu63qZhOtkKoFECgYBdUVFWEUAHdaE6fmbz1Vg9OVW1DGoshFATKNxa\n' +
    'J7b4ElGf9hS7ch4cWEmp57v5spvksbTbhsGwMv+5uvqNQFHN54p7/xh02LMcvUKH\n' +
    'PLP42NRJrZba0Y4yLn3GAeeW7wek5zKKCVyZuCEm1Xvbyj+pVI0MeDfMeVycASi9\n' +
    'Emi4cwKBgGlyApKOOxPGpaXSfjkeIpkPnDk9sQNpMr0zXQqZpg/OgPZmZNHdAOBg\n' +
    'RZycinkxOLbCl8JLVqqRWdkMaDBQScMGBQce7FEFwKCOyts9uakZcRCkF5F5E0H8\n' +
    'eZB2qW17Y/X/+rA0veFlI6Ms2D/aS5q/tknlhd2BMA2gGCHbasCH\n' +
    '-----END RSA PRIVATE KEY-----\n';
process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = 'localhost';

export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  moduleNameMapper: {
    '^(\\.\\.?/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        ignoreDeprecations: '6.0',
      },
    }],
  },
} as JestConfigWithTsJest;
