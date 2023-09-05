import {appInit} from './app.js'
import process from 'process'

const PORT = parseInt(process.env.PORT ?? '') || 3000

const app = await appInit()
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})

