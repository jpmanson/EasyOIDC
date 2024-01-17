import bottle
from beaker.middleware import SessionMiddleware

session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './data',
    'session.auto': True
}
app = SessionMiddleware(bottle.app(), session_opts)

@bottle.route('/test')
def test():
  s = bottle.request.environ.get('beaker.session')
  s['test'] = s.get('test',0) + 1
  s.save()
  return 'Test counter: %d' % s['test']

bottle.run(app=app)