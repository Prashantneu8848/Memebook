import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import hmac
import random
import string
import urllib
import cgi

from google.appengine.ext import db
from google.appengine.api import images


template_dir = jinja2.FileSystemLoader(searchpath="./")
jinja_env = jinja2.Environment(loader=template_dir, autoescape=True)

secret = "Qj!A*(d2_s)f22[!sd"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def hash_str(s):
    key = secret
    return hmac.new(key, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # Renders the template in the form of plain python strings.
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # Writes the template in the browser.
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Creates the cookie for the user.
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Delets the cookie for that user.
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(Handler):
    def get(self):
        self.render('homepage.html')


def make_salt(length=5):
    return ''.join(random.choice(string.ascii_letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256((name + pw + salt).encode('utf-8')).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    image = db.BlobProperty()

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogFront(Handler):
    def get(self):
        self.username = self.request.get('username')
        if valid_username(self.username):
            posts = Post.all().order('-created')
            self.response.out.write('<html><body>')
            self.response.out.write('<a href="/blog/newpost">post</a> <br> <a href="logout">logout</a>')
            for post in posts:
                self.response.out.write('<div><img src="/img?img_id=%s"></img>' %
                                    str(post.key()))
                self.response.out.write('<blockquote>%s</blockquote></div>' %
                                    cgi.escape(post.content))
        else:
            self.redirect('/')

class Image(webapp2.RequestHandler):
    def get(self):
        post_key = db.Key(self.request.get('img_id'))
        post = db.get(post_key)
        if post.image:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(post.image)
        else:
            self.response.out.write('No image')

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        # self.response.out.write(post.subject)
        # self.response.out.write(post.content)
        #self.response.headers['Content-Type'] = "image/png"
        # self.response.out.write(post.image)
        self.render("permalink.html", post = post)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        image = self.request.get('img')
        image = images.resize(image, 32, 32)

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, image = image)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject, image and content, please!"
            self.render("newpost.html", subject=subject, content=content, image = image, error=error)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Signup(Handler):

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

    def valid_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return not email or EMAIL_RE.match(email)

    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        username_valid = valid_username(self.username)
        password_valid = self.valid_password(self.password)
        email_valid = self.valid_email(self.email)

        params = dict(username= self.username, email= self.email)

        if not username_valid:
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not password_valid:
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "The passwords do not match"
            have_error = True

        if not email_valid:
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        # Implemented by child class.
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog?username=' + self.username)

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        u = User.login(self.username, self.password)
        if u:
            self.login(u)
            self.redirect('/blog?username=' + self.username)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/img', Image),
                               ('/logout', Logout),
                               ('/blog', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ],
                              debug=True)
