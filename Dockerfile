FROM python:3.9-buster as base

FROM base as builder

RUN mkdir /install
WORKDIR /install
COPY ./requirements.txt  /
RUN pip install --upgrade pip setuptools && \
    pip install --target /install -r /requirements.txt

FROM base

ARG USER_ID
ARG GROUP_ID
ARG USER_NAME
ARG GROUP_NAME

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    if getent passwd ${USER_NAME:-ubuntu} ; then userdel -f ${USER_NAME:-ubuntu}; fi &&\
    if getent group ${GROUP_ID:-0} ; then GROUP_NAME="$(getent group ${GROUP_ID:-0} | cut -d: -f1)"; fi &&\
    if ! getent group ${GROUP_NAME:-ubuntu} ; then groupadd -g ${GROUP_ID} ${GROUP_NAME:-ubuntu} ; fi &&\
    useradd -l -u ${USER_ID} -g ${GROUP_NAME:-ubuntu} ${USER_NAME:-ubuntu} \
    ;fi

RUN echo "Building image for user ${USER_NAME:-ubuntu}:${GROUP_NAME:-ubuntu} with IDs ${USER_ID:-0}:${GROUP_ID:-0}"

COPY --chown=${USER_NAME:-ubuntu}:${GROUP_NAME:-ubuntu} --from=builder /install /usr/local/lib/python3.9/site-packages

USER ${USER_NAME:-ubuntu}

WORKDIR /app
ENTRYPOINT ["python3", "apk_scanner.py"]
CMD ["idle"]
