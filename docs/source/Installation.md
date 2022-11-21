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