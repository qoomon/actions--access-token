# syntax=docker/dockerfile:1

FROM node:20-alpine as build
COPY . /app
WORKDIR /app

RUN --mount=type=bind,src=package.json,target=package.json \
    --mount=type=bind,src=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci

ENV NODE_ENV production
RUN npm run build


FROM gcr.io/distroless/nodejs20-debian12:latest as image
COPY --from=build /app/dist/ /app
WORKDIR /app

EXPOSE 3000
ENV NODE_ENV production
CMD ["index.js"]

