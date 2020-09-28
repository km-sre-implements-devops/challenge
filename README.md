
# Para poder usar la api hay que logearse con usuario y contraseña, el usuario debe existir previamente en la base de datos
# por seguridad el password debe estar como variable de entorno
export BASIC_AUTH_USER=admin BASIC_AUTH_PASSWORD=primer_password_sin_hash

curl -L -X POST 'http://localhost:5000/shield/login' -H "Authorization: Basic $(echo -ne "$BASIC_AUTH_USER:$BASIC_AUTH_PASSWORD" | base64 --wrap 0)" -H "Content-Type: application/json"
# Shield devolvera un toker para ser usado en las llamadas a la api.

# Para hacer un request y traer toda la blacklist completa
curl -L -X POST 'http://localhost:5000/shield/out/blacklist' \
-H 'x-access-tokens: TOKEN_FROM_LOGIN' \
-H 'Content-Type:  application/json

# Se debe ingresar el token devuelto por login
# ejemplo:

curl -L -X POST 'http://localhost:5000/shield/out/blacklist' \
-H 'x-access-tokens: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjAxMjUyMjI3fQ.q2X0PpTdY8LDtnvU27E_kh_D9bRdAQ20TLDSXOvSEks' \
-H 'Content-Type:  application/json
# Respuesta
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


# Para hacer un request y traer la blacklist sin las ip de la whitelist

$ curl -L -X POST 'http://localhost:5000/shield/out/blacklist_cleaned' -H 'x-access-tokens: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjAxMjUyMjI3fQ.q2X0PpTdY8LDtnvU27E_kh_D9bRdAQ20TLDSXOvSEks' -X 'Content-Type: application/json'

# Respuesta
{
  "blacklist_cleaned": 
  [     
    "45.154.35.217", 
    "45.154.35.220", 
    "45.154.35.215", 
    "209.141.58.188"
  ]
}

# Para agregar una ip a whitelist y quede registrada en la base de datos
curl -L -X POST 'http://localhost:5000/shield/in/whitelist' -H 'x-access-tokens: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZXhwIjoxNjAxMjUyMjI3fQ.q2X0PpTdY8LDtnvU27E_kh_D9bRdAQ20TLDSXOvSEks' -H 'Content-Type: application/json' -d '{ "ip" : "45.154.35.213" }'
# Respuesta
{
  "message": "Ip: 45.154.35.213 registered successfully"
}