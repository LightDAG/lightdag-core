FROM ubuntu:16.04

ARG NETWORK=live

ENV BOOST_ROOT=/tmp/boost_install

ADD ci /tmp/ci

RUN apt-get update -qq && apt-get install -yqq \
    build-essential \
    cmake \
    g++ \
    wget && \
    /tmp/ci/bootstrap_boost.sh -m

ADD ./ /tmp/src

RUN mkdir /tmp/build && \
    cd /tmp/build && \
    cmake /tmp/src -DBOOST_ROOT=${BOOST_ROOT} -DACTIVE_NETWORK=lightdag_${NETWORK}_network && \
    make lightdag_node && \
    cd .. && \
    echo ${NETWORK} > /etc/lightdag-network

FROM ubuntu:16.04
COPY --from=0 /tmp/build/lightdag_node /usr/bin
COPY --from=0 /etc/lightdag-network /etc
COPY docker/node/entry.sh /entry.sh
COPY docker/node/config /usr/share/lightdag/config
RUN chmod +x /entry.sh
CMD ["/bin/bash",  "/entry.sh"]
