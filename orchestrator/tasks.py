from celery import Celery

app = Celery('tasks', broker = 'sqla+sqlite:///template_celery.sqlite')

@app.task
def add(x,y):
    return x+y