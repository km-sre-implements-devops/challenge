FROM python:3.8.6-slim as dependencies

# remueve el SUID desde todos los binarios
RUN for file in `find / -not \( -path /proc -prune \) -type f -perm /6000`; \
  do \
  echo "remove SUID for $file"; \
  chmod a-s $file; \
  done

# creacion de un usuario non-root para levantar la app
ENV USER=appuser UID=1000 GID=1000

RUN useradd -m ${USER} --uid=${UID} && echo "${USER}:$(openssl passwd -1 appuser)" | chpasswd

USER ${UID}:${GID}

LABEL maintainer="k.michael@protonmail.ch"
WORKDIR /home/${USER}/app
ENV PATH=$HOME/.local/bin:$PATH

ENV SECRET_KEY="WILL_GIVEN_IN_DOCKER_RUN" 
ENV FLASK_APP=run.py

#ej: develoment, stage, prod
ENV FLASK_ENV="WILL_GIVEN_IN_DOCKER_RUN" 

COPY meli_shield/ .
COPY requirements.txt .

RUN pip install -r requirements.txt --no-warn-script-location

EXPOSE 8080
ENTRYPOINT ["python3", "run.py"]