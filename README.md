# Shield 

## Shield use:

$ git clone git@github.com:kmichael-devops/challenge.git
$ docker build -t shield .

Para levantar el contenedor , se debe proporcionar el variable de entorno SECRET_KEY
$ export SECRET_KEY=contraseñaMuySecreta
$ docker run -p 8080:8080 --name shield -e SECRET_KEY=${SECRET_KEY} -e FLASK_ENV=development -d shield


#### Para poder usar la api hay que logearse con usuario y contraseña, el usuario debe existir previamente en la base de datos
#### El password debe ser entregado como variable de entorno

$ export BASIC_AUTH_USER=admin BASIC_AUTH_PASSWORD=primer_password_sin_hash
$ curl -L -X POST 'http://localhost:8080/shield/login' -H "Authorization: Basic $(echo -ne "$BASIC_AUTH_USER:$BASIC_AUTH_PASSWORD" | base64 --wrap 0)" -H "Content-Type: application/json"

Shield devolvera un token para ser usado en las llamadas a la api.

#### Respuesta:
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjAxMjYzNjc3fQ.uNY_GUtAEb_QiP8hbaHOVCwDRQ_nXXeN4TK2q4fp6IE"
}


#### Para hacer un request y traer blacklist completa

Reemplazar TOKEN_FROM_LOGIN por token entregado por login
$ curl -L -X POST 'http://localhost:8080/shield/out/blacklist' \
-H 'x-access-tokens: TOKEN_FROM_LOGIN' \
-H 'Content-Type:  application/json

#### Respuesta:
{
  "blacklist": 
  [ 
    "45.154.35.210", 
    "45.154.35.216", 
    "45.154.35.212", 
    "45.154.35.222",   
    "45.154.35.217", 
    "45.154.35.220", 
    "45.154.35.215", 
    "209.141.58.188"
  ]
}


##### Para hacer un request y traer blacklist sin las ip de whitelist

$ curl -L -X POST 'http://localhost:8080/shield/out/blacklist_cleaned' -H 'x-access-tokens: TOKEN_FROM_LOGIN' -H 'Content-Type: application/json'

#### Respuesta:
{
  "blacklist_cleaned": 
  [     
    "45.154.35.217", 
    "45.154.35.220", 
    "45.154.35.215", 
    "209.141.58.188"
  ]
}


#### Para agregar una ip a whitelist y quede registrada en la base de datos

$ curl -L -X POST 'http://localhost:8080/shield/in/whitelist' -H 'x-access-tokens: TOKEN_FROM_LOGIN' -H 'Content-Type: application/json' -d '{ "ip" : "45.154.35.213" }'

#### Respuesta:
{
  "message": "Ip: 45.154.35.213 registered successfully"
}


#### Healthcheck path

$ curl -L -X POST 'http://localhost:8080/shield/healthcheck' -H 'x-access-tokens: TOKEN_FROM_LOGIN' -H 'Content-Type: application/json'

#### Respuesta:
{
  "shield": "ok"
}

### Kubernetes 3 replicas con service LB

$ cd k8s/
$ kubectl appy -f .

### AWS WAF

Para implementar shield en cloud
modificar waf rules con el script para blockear ip desde la blacklist y admitir ls de whitelist