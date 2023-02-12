# rufs-base-rust
Restful Utilities for Full Stack - Base Modules and Microservices to Rust

Offer base crate to rufs compliance microservices

You need Rust installed and PostgreSql server already running with your database.

## First Step

Open terminal and clone this repository with `git clone https://github.com/alexsandrostefenon/rufs-base-rust`.

Requires Rust version >= 1.63

## Run Ecosystem

## PostgreSql setup

create database :

sudo su postgres;

or

su -c "su postgres";

export PGDATABASE=postgres;
psql -c "CREATE USER development WITH CREATEDB LOGIN PASSWORD '123456'";
psql -c 'CREATE DATABASE rufs_base_development WITH OWNER development';
exit;

Note, database "rufs_base_development" is only for testing purposes.

### Run Ecosystem

#Only to clean already existent configuration :
`
rm openapi-base-rust.json;
`
#Only to clean already existent testing data :

`
export PGHOST=localhost;
export PGPORT=5432;
export PGUSER=development;
export PGPASSWORD=123456;

psql rufs_base_development -c "DROP DATABASE IF EXISTS rufs_base" &&
psql rufs_base_development -c "CREATE DATABASE rufs_base";
`

Download browser webapp with :
`
git clone https://github.com/alexsandrostefenon/rufs-base-es6;
git clone https://github.com/alexsandrostefenon/rufs-crud-es6;`
`

#Execute rufs-proxy to load and start microservices :

cd ./rufs-base-rust &&
PGHOST=localhost PGPORT=5432 PGUSER=development PGPASSWORD=123456 PGDATABASE=rufs_base go test -timeout 3600s -run ^TestExternal$ -v -args --webapp ../rufs-base-es6/webapp ../rufs-crud-es6/webapp

## NFE test :
cd ./rufs-base-go;
rm *openapi-nfe.json; \
PGHOST=localhost PGPORT=5432 PGUSER=development PGPASSWORD=123456 psql rufs_nfe_development -c "DROP DATABASE IF EXISTS rufs_nfe" &&
PGHOST=localhost PGPORT=5432 PGUSER=development PGPASSWORD=123456 psql rufs_nfe_development -c "CREATE DATABASE rufs_nfe" &&
PATH=$PATH:/usr/lib/go-1.18/bin $HOME/go/bin/dlv dap --check-go-version=false --listen=127.0.0.1:33797 --log-dest=3;
PATH=$PATH:/usr/lib/go-1.18/bin $HOME/go/bin/dlv test --headless --listen=127.0.0.1:33797 --log-dest=3;
PGHOST=localhost PGPORT=5432 PGUSER=development PGPASSWORD=123456 PGDATABASE=rufs_nfe go test -timeout 3600s -run ^TestNfe$
#./rufs-base-go/__debug_bin -test.run ^TestNfe$


## Web application

check if rest is active

`
curl -X 'GET' http://localhost:9090/rest/login -d '{"user": "admin", "password": "21232f297a57a5a743894a0e4a801fc3"}' -H 'Connection: close' -H 'content-type: application/json';
`

In EcmaScript2017 compliance browser open url http://localhost:9090

For custom service configuration or user edition, use user 'admin' with password 'admin'.
rufs-base-es6/README.
