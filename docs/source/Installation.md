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

The app administrator can enable/disable the extraction of source IPs for specific honeypots from the Django Admin.
This is used for honeypots that are not specifically implemented to extract additional information (so not Log4Pot and Cowrie).

Note that GreedyBear *needs* a running instance of ElasticSearch of a TPoT to function.
If you don't have one, you can make the following changes to make GreeyBear spin up it's own ElasticSearch and Kibana instances.
(...Care! This option would require enough RAM to run the additional containers. Suggested is >=16GB):

1. In ```docker/env_file```, set the variable ```ELASTIC_ENDPOINT``` to ```http://elasticsearch:9200```.
2. Add ```:docker/elasticsearch.yml``` to the last defined ```COMPOSE_FILE``` variable or uncomment the ```# local development with elasticsearch container``` block in ```.env``` file.


### Environment configuration
In the `env_file`, configure different variables as explained below.

**Strongly recommended** variable to set:
* `DEFAULT_FROM_EMAIL`: email address used for automated correspondence from the site manager (example: `noreply@mydomain.com`)
* `DEFAULT_EMAIL`: email address used for correspondence with users (example: `info@mydomain.com`)
* `RECAPTCHA_SECRET_KEY_IO_LOCAL`: your recaptcha secret key internal deployment
* `RECAPTCHA_SECRET_KEY_IO_PUBLIC`: your recaptcha secret key for public deployment

* `EMAIL_HOST`: the host to use for sending email with SMTP
* `EMAIL_HOST_USER`: username to use for the SMTP server defined in EMAIL_HOST
* `EMAIL_HOST_PASSWORD`: password to use for the SMTP server defined in EMAIL_HOST. This setting is used in conjunction with EMAIL_HOST_USER when authenticating to the SMTP server.
* `EMAIL_PORT`: port to use for the SMTP server defined in EMAIL_HOST.
* `EMAIL_USE_TLS`: whether to use an explicit TLS (secure) connection when talking to the SMTP server, generally used on port 587. 
* `EMAIL_USE_SSL`: whether to use an implicit TLS (secure) connection when talking to the SMTP server, generally used on port 465.

**Optional configuration**:
* `SLACK_TOKEN`: Slack token of your Slack application that will be used to send/receive notifications
* `SLACK_CHANNEL`: ID of the Slack channel you want to post the message to



## Update and Re-build

### Rebuilding the project / Creating custom docker build
If you make some code changes and you like to rebuild the project, follow these steps:

1. Be sure that your `.env` file has a `COMPOSE_FILE` variable which mounts the `docker/local.override.yml` compose file.
2. `docker-compose build` to build the new docker image.
1. Start the containers with `docker-compose up`.

### Update to the most recent version
To update the project with the most recent available code you have to follow these steps:

```bash
$ cd <your_greedy_bear_directory> # go into the project directory
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