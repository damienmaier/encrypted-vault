mkdir certificate_for_client
mkdir certificate_for_server
mkdir root_certificate_private_key

openssl req -x509 -days 365 -subj "/C=ccc/ST=ststst/L=lll/O=ooo/CN=cncn" -addext basicConstraints=critical,CA:true -nodes -out certificate_for_client/ca.pem -keyout root_certificate_private_key/ca.key
openssl req -CA certificate_for_client/ca.pem -CAkey root_certificate_private_key/ca.key -subj "/C=/ST=/L=/O=/CN=localhost" -addext basicConstraints=critical,CA:false -nodes -out certificate_for_server/server_certificate.pem -keyout certificate_for_server/server_certificate_key.key