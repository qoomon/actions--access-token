import {serve} from '@hono/node-server'
import {appInit} from './app.js'
import process from 'process'

const app = await appInit()

const port = parseInt(process.env.PORT ?? '') || 3000
console.log(`Server is listening on port ${port}`)
serve({fetch: app.fetch, port})
