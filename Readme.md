# Technical exercise

## Introduction
This application receives a threat from a curl command and  listens to a webhook from Sqreen.io.  
Local callback url is not accessible from Sqreen.io though. Another curl command simulates the webhook usage.  

Bakends:
- a logger writing errors a in log file
- a slack-app web client which sends errors into a channel

Workers:  
As alerts and logging should not block the main thread, background workers are running. You can configure the nb of threads by setting NB_WORKER_THREAD env var. 

Tests:  
- test_backend.py for testing all of the dispatchers

## Install
> python > 3.5
```shell script
# install
pip install venv
source venv/bin/activate
pip install -r requirements.txt

# run the flask application
SQREEN_SECRET=[SCREEN_APP_SECRET] \
SLACK_TOKEN=[SLACK_TOKEN] \
SLACK_CHANNEL=[SLACK_CHANNEL] \
NB_WORKER_THREAD=2 \
LOG_PATH=logs.txt \
FLASK_APP=app.py \
FLASK_ENV=development \
FLASK_DEBUG=0 \
bash -c 'python -m flask run'
```

## Sqreen integration
app.js:
```python
import sqreen
sqreen.start()
```


### Send a threat
```shell script
bash scripts/send_threat.sh
```

### Receive webhook
```shell script
bash scripts/receive_security_alert.sh
# stress test background workers
# bash scripts/receive_security_alert_stress.sh
```

## Test
```shell script
python test_backend.py
```