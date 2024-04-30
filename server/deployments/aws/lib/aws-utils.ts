import {SecretsManager} from '@aws-sdk/client-secrets-manager'

/**
 * Secrets Manager Helper is a wrapper around AWS Secrets Manager client
 */
export class SecretsManagerHelper {
  private client: SecretsManager

  /**
   * Create a new SecretsManagerHelper
   * @param client - AWS Secrets Manager client
   */
  constructor(client: SecretsManager) {
    this.client = client
  }

  /**
   * Get secret string from AWS Secrets Manager
   * @param secretId - secret id
   * @return secret string
   */
  public async getSecretString(secretId: string) : Promise<string> {
    const secret = await this.client.getSecretValue({SecretId: secretId})
    if (secret.SecretString === undefined) {
      throw Error('Secret is not a string')
    }
    return secret.SecretString
  }

  /**
   * Get secret object from AWS Secrets Manager
   * @param secretId - secret id
   * @return secret string
   */
  public async getSecretObject(secretId: string): Promise<unknown> {
    return await this.getSecretString(secretId).then((it) => JSON.parse(it))
  }
}
