# Contribute

## Rules
GreedyBear welcomes contributors from anywhere and from any kind of education or skill level. We strive to create a community of developers that is welcoming, friendly and right.

For this reason it is important to follow some easy rules based on a simple but important concept: **Respect**.

* Before starting to work on an issue, you need to get the approval of one of the maintainers. Therefore please ask to be assigned to an issue. If you do not that but you still raise a PR for that issue, your PR can be rejected. This is a form of respect for both the maintainers and the other contributors who could have already started to work on the same problem.

* When you ask to be assigned to an issue, it means that you are ready to work on it. When you get assigned, take the lock and then you disappear, you are not respecting the maintainers and the other contributors who could be able to work on that. So, after having been assigned, you have a week of time to deliver your first *draft* PR. After that time has passed without any notice, you will be unassigned.

* Before asking questions regarding how the project works, please read *through all the documentation* and [install](https://greedybear.readthedocs.io/en/latest/Installation.html) the project on your own local machine to try it and understand how it basically works. This is a form of respect to the maintainers.

* Once you started working on an issue and you have some work to share and discuss with us, please raise a draft PR early with incomplete changes. This way you can continue working on the same and we can track your progress and actively review and help. This is a form of respect to you and to the maintainers.

* When creating a PR, please read through the sections that you will find in the PR template and compile it appropriately. If you do not, your PR can be rejected. This is a form of respect to the maintainers.

## Code Style
Keeping to a consistent code style throughout the project makes it easier to contribute and collaborate. We make use of [`psf/black`](https://github.com/psf/black) and [isort](https://pycqa.github.io/isort/) for code formatting and [`flake8`](https://flake8.pycqa.org) for style guides.

## How to start (Setup project and development instance)
To start with the development setup, make sure you go through all the steps in [Installation Guide](https://greedybear.readthedocs.io/en/latest/Installation.html) and properly installed it.

Please create a new branch based on the **develop** branch that contains the most recent changes. This is mandatory.

`git checkout -b myfeature develop`

Then we strongly suggest to configure [pre-commit](https://github.com/pre-commit/pre-commit) to force linters on every commits you perform:
```bash
# create virtualenv to host pre-commit installation
python3 -m venv venv
source venv/bin/activate
# from the project base directory
pip install pre-commit
pre-commit install
```


Remember that whenever you make changes, you need to rebuild the docker image to see the reflected changes.


#### NOTE about documentation:

If you made any changes to an existing model/serializer/view, please run the following command to generate a new version of the API schema and docs:

```bash
docker exec -it greedybear_uwsgi python manage.py spectacular --file docs/source/schema.yml && make html
```

### Frontend

To start the frontend in "develop" mode, you can execute the startup npm script within the folder `frontend`:

```bash
cd frontend/
# Install
npm i
# Start
DANGEROUSLY_DISABLE_HOST_CHECK=true npm start
# See https://create-react-app.dev/docs/proxying-api-requests-in-development/#invalid-host-header-errors-after-configuring-proxy for why we use that flag in development mode
```

Most of the time you would need to test the changes you made together with the backend. In that case, you would need to run the backend locally too:

```commandline
docker-compose up
```

#### Certego-UI

The GreedyBear Frontend is tightly linked to the [`certego-ui`](https://github.com/certego/certego-ui) library. Most of the React components are imported from there. Because of this, it may happen that, during development, you would need to work on that library too.
To install the `certego-ui` library, please take a look to [npm link](https://docs.npmjs.com/cli/v8/commands/npm-link) and remember to start certego-ui without installing peer dependencies (to avoid conflicts with GreedyBear dependencies):

```bash
git clone https://github.com/certego/certego-ui.git
# change directory to the folder where you have the cloned the library
cd certego-ui/
# install, without peer deps (to use packages of GreedyBear)
npm i --legacy-peer-deps
# create link to the project (this will globally install this package)
sudo npm link
# compile the library
npm start
```

Then, open another command line tab, create a link in the `frontend` to the `certego-ui` and re-install and re-start the frontend application (see previous section):

```bash
cd frontend/
npm link @certego/certego-ui
```

This trick will allow you to see reflected every changes you make in the `certego-ui` directly in the running `frontend` application.

##### Example application

The `certego-ui` application comes with an example project that showcases the components that you can re-use and import to other projects, like GreedyBear:

```bash
# To have the Example application working correctly, be sure to have installed `certego-ui` *without* the `--legacy-peer-deps` option and having it started in another command line
cd certego-ui/
npm i
npm start
# go to another tab
cd certego-ui/example/
npm i
npm start
```

## Create a pull request

### Remember!!!
Please create pull requests only for the branch **develop**. That code will be pushed to master only on a new release.

Also remember to pull the most recent changes available in the **develop** branch before submitting your PR. If your PR has merge conflicts caused by this behavior, it won't be accepted.

### Install testing requirements
Run `pip install -r requirements/test-requirements.txt` to install the requirements to validate your code.

#### Pass linting and tests
 Run `psf/black` to lint the files automatically, then `flake8` to check and `isort`.

 (if you installed `pre-commit` this is performed automatically at every commit)

  if you get any errors, fix them.
  Once you make sure that everything is working fine, please squash all of our commits into a single one and finally create a pull request.

