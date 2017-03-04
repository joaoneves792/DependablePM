#! /bin/bash

PASSWORD="123456"
ROOTDIR="generated-keystores"
SERVER="DependablePMServer"
CLIENT="Client"

function setupCA {
	#Generate CA keys
	keytool -genkeypair -alias cakey -dname "cn=DepPMCA, ou=SEC, o=IST, c=PT" -keyalg RSA -keysize 2048 -validity 365 -keystore CA.jks -keypass $PASSWORD -storepass $PASSWORD
	#Export CA keys to format openssl can understand
	keytool -importkeystore -srckeystore CA.jks -destkeystore temp.p12 -deststoretype PKCS12 -srcalias cakey -srcstorepass $PASSWORD -keypass $PASSWORD -deststorepass $PASSWORD -destkeypass $PASSWORD
	#Extract the cacert
	openssl pkcs12 -in temp.p12 -nokeys -passin pass:$PASSWORD -out cacert.pem
	#Extract the ca key
	openssl pkcs12 -in temp.p12 -nodes -nocerts -passin pass:$PASSWORD -out key.pem
	rm temp.p12
}

function createCSR {
	name=$1
	keystore="$1".jks
	#Create the keystore and generate the keys
	keytool -genkeypair -alias mykey -dname "cn=$name, ou=SEC, o=IST, c=PT" -keyalg RSA -keysize 2048 -validity 365 -keystore $keystore -keypass $PASSWORD -storepass $PASSWORD
	#Create a csr
	keytool -certreq -alias mykey -keypass $PASSWORD -keystore $keystore -storepass $PASSWORD -file $name.csr
}

function signCSR {
	name=$1
	openssl x509 -req -CA ../cacert.pem -CAkey ../key.pem -in $name.csr -out $name.cer -days 365 -CAcreateserial
}

function importCAcert {
	keystore="$1".jks
	keytool -import -keystore $keystore -file ../cacert.pem -alias cacert -storepass $PASSWORD -noprompt
}

function importServerCert {
	keystore="$1".jks
	server=$2
	keytool -importkeystore -srckeystore ./CA.jks -destkeystore ./"$1"/$keystore -srcstorepass $PASSWORD -deststorepass $PASSWORD -srcalias $server
}

function importCertToCAKeystore {
	cert=$1
	alias=$2
	keytool -import -keystore ../CA.jks -file $cert -alias $alias -storepass $PASSWORD
}

function importMyCert {
	cert=$1
	keystore="$2".jks
	keytool -import -keystore $keystore -file $cert -alias "mycert" -storepass $PASSWORD
}

function createEntity {
	entity=$1
	mkdir $entity
	cd $entity
	createCSR $entity
	signCSR $entity
	importCAcert $entity
	importCertToCAKeystore $entity.cer $entity
	importMyCert $entity.cer $entity
	rm $entity.cer $entity.csr
	cd ..
}

mkdir $ROOTDIR
cd $ROOTDIR
setupCA

createEntity "$SERVER"
createEntity "$CLIENT"1
importServerCert "$CLIENT"1 "$SERVER"

#createEntity "$CLIENT"2

rm key.pem
