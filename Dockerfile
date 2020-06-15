# To build use:
# docker build -t my .; docker run -it my
FROM ubuntu:20.04
MAINTAINER Ihor Ivlev <ivlev.igor@gmail.com>

LABEL description="A linux C++ build environment."

ENV TZ=Europe/Kiev
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
  gcc \
  clang \
  cmake \
  libgtest-dev \
  g++ \
  make \
  binutils-dev \
  libssl-dev \
  git \
  pkg-config

RUN mkdir /build
WORKDIR /build

ADD . /build

RUN ["./configure"]

WORKDIR /build/build
RUN ["make", "-j9"]
RUN ["make", "test"]

WORKDIR /build/build/app
RUN ["./openssl_app", "--public-key", "pub.key", "--filename", "openssl_app", "--out-filename", "openssl_app.ssl"]
RUN ["./openssl_app", "--private-key", "priv.key", "--filename", "openssl_app.ssl", "--out-filename", "openssl_app.enc"]

RUN stringarray=$(md5sum openssl_app openssl_app.enc | tr '\n' ' '); A=$(echo ${stringarray} | cut -d ' ' -f1); B=$(echo ${stringarray} | cut -d ' ' -f3); test $A = $B