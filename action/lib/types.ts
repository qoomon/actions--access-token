import type {OutgoingHttpHeaders} from 'http'

export type GitHubAppPermissions = Record<string, string>

export type GitHubAccessTokenResponse = {
  token: string
  expires_at: string
  repositories: string[]
  permissions: GitHubAppPermissions
}

export type HttpClientRequest = {
  verb: string,
  requestUrl: string,
  data: string | NodeJS.ReadableStream | null,
  additionalHeaders?: OutgoingHttpHeaders
}
