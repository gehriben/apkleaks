FROM python:3.9-buster as base

FROM base as builder
ARG REPO_USER
ARG REPO_PASSWORD

RUN mkdir /install
WORKDIR /install
COPY ./requirements.txt  /
RUN echo "machine isg-python-repository.cloudlab.zhaw.ch login ${REPO_USER} password ${REPO_PASSWORD}" > /root/.netrc && \
    chown root /root/.netrc && \
    chmod 0600 /root/.netrc && \
    pip install --upgrade pip setuptools && \
    pip install --target /install -r /requirements.txt && \
    rm /root/.netrc

FROM base

ARG USER_ID
ARG GROUP_ID
ARG USER_NAME
ARG GROUP_NAME

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:openjdk-r/ppa && \
    apt-get install -y openjdk-11-jre-headless && \
    apt-get clean

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    if getent passwd ${USER_NAME:-ubuntu} ; then userdel -f ${USER_NAME:-ubuntu}; fi &&\
    if getent group ${GROUP_ID:-0} ; then GROUP_NAME="$(getent group ${GROUP_ID:-0} | cut -d: -f1)"; fi &&\
    if ! getent group ${GROUP_NAME:-ubuntu} ; then groupadd -g ${GROUP_ID} ${GROUP_NAME:-ubuntu} ; fi &&\
    useradd -l -u ${USER_ID} -g ${GROUP_NAME:-ubuntu} ${USER_NAME:-ubuntu} \
    ;fi

RUN echo "Building image for user ${USER_NAME:-ubuntu}:${GROUP_NAME:-ubuntu} with IDs ${USER_ID:-0}:${GROUP_ID:-0}"

COPY --chown=${USER_NAME:-ubuntu}:${GROUP_NAME:-ubuntu} --from=builder /install /usr/local/lib/python3.9/site-packages

# USER ${USER_NAME:-ubuntu}
USER ${ubuntu}

WORKDIR /app
ENTRYPOINT ["python3", "cli.py"]
CMD ["do-nothing"]
