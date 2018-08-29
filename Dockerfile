FROM ruby:2.5.1-alpine3.7

RUN apk -X http://dl-cdn.alpinelinux.org/alpine/edge/testing add xml2rfc \
  && apk add py-setuptools py-six py-requests \
  && gem install kramdown-rfc2629
