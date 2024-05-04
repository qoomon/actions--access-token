# syntax=docker/dockerfile:1

FROM node:20-alpine as build

WORKDIR /usr/src/app

RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .

ENV NODE_ENV production

RUN npm run build

FROM node:20-alpine as image

WORKDIR /srv

COPY --from=build /usr/src/app/dist/package.json .
COPY --from=build /usr/src/app/dist/index.js .

ENV NODE_ENV production

USER node

EXPOSE 3000

CMD node index.js

