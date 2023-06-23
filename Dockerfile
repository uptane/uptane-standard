FROM ruby:alpine

RUN  apk add py-setuptools py-six py-requests py3-pip \
  && pip install xml2rfc \
  && gem install kramdown-rfc2629
