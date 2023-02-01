# Installation

Start by cloning the project
```bash
# clone the Greedybear project repository
git clone https://github.com/honeynet/GreedyBear
cd GreedyBear/

# construct environment files from templates
cp .env_template .env
cd docker/
cp env_file_template env_file
cp env_file_postgres_template env_file_postgres
cd ..
```

Now you can start by building the image using docker-compose and run the project.

```bash
# build the image locally
docker-compose build

# start the app
docker-compose up

# now the app is running on http://localhost:80

# shut down the application
docker-compose down
```
*Note:* To create a superuser run the following:
```bash
docker exec -ti greedybear_uwsgi python3 manage.py createsuperuser
```

In `greedybear/consts.py`, you might want to change the variable `GENERAL_HONEYPOTS` to include/exclude the extraction of source IPs for specific honeypots.
This is used for honeypots that are not specifically implemented to extract additional information (so not Log4Pot and Cowrie).

Note that GreedyBear *needs* a running instance of ElasticSearch of a TPoT to function.
If you don't have one, you can make the following changes to make GreeyBear spin up it's own ElasticSearch and Kibana instances.
(...Care! This option would require enough RAM to run the additional containers. Suggested is >=16GB):

1. In ```docker/env_file```, set the variable ```ELASTIC_ENDPOINT``` to ```http://elasticsearch:9200```.
2. Add ```:docker/elasticsearch.yml``` to the last defined ```COMPOSE_FILE``` variable or uncomment the ```# local development with elasticsearch container``` block in ```.env``` file.

## Update and Re-build

### Rebuilding the project / Creating custom docker build
If you make some code changes and you like to rebuild the project, follow these steps:

1. Be sure that your `.env` file has a `COMPOSE_FILE` variable which mounts the `docker/local.override.yml` compose file.
2. `docker-compose build` to build the new docker image.
1. Start the containers with `docker-compose up`.

### Update to the most recent version
To update the project with the most recent available code you have to follow these steps:

```bash
$ cd <your_intel_owl_directory> # go into the project directory
$ git pull # pull new repository changes
$ docker pull intelowlproject/greedybear:prod # pull new docker images
$ docker-compose down # stop and destroy the currently running GreedyBear containers 
$ docker-compose up # restart the GreedyBear application
```


## Installer for TPot Instance
The file 'installer_on_tpot.sh' allows the automatic installation of Greedybear on an existing TPot instance.
You can choose the type of Greedybear you want to install (http, https or local).
The installer will either clone Greedybear to '/opt/GreedyBear' or if Greedybear exists on your system you need to input the absolute path to the existing Greedybear folder.
It will prompt you for the necessary information/secrets needed.

Example: `sudo ./installer.sh --type=http --folder=/opt/GreedyBear`

<div class="admonition warning">
<p class="admonition-title">Warning</p>
This installer is not officialy supported neither by Greedybear nor by TPOT maintainers.
It must be considered as a POC to have GB and TPOT installed in the same place.
Greedybear is supported to be executed only in a separate instance and to connect externally with the TPOTs.
</div>