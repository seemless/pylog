__author__ = 'matthew'

import argparse
import numpy as np
import scipy.optimize
import pymongo
import time

def logistic(z):
  x = np.exp(-z)
  ret = 1.0 / (1.0 + x)
  del x
  return ret

def predict(w, x):
  x = logistic(np.dot(w, x))
  ret = x > 0.5 or -1
  del x
  return  ret

def log_likelihood(X, Y, w, C=0.1):
  #big
  x_dot_w = np.dot(X, w)
  y_dot_x = Y * x_dot_w
  del x_dot_w 
  logis = logistic(y_dot_x)

  #big
  w_dot_w = np.dot(w,w)

  log_like = np.sum(np.log(logis)) - C/2 * w_dot_w
  return log_like

def log_likelihood_grad(X, Y, w, C=0.1):
  K = len(w)
  N = len(X)
  s = np.zeros(K)

  for i in range(N):
    s += Y[i] * X[i] * logistic(-Y[i] * np.dot(X[i], w))

  s -= C * w

  return s

def grad_num(X, Y, w, f, eps=0.00001):
  K = len(w)
  ident = np.identity(K)
  g = np.zeros(K)

  for i in range(K):
    g[i] += f(X, Y, w + eps * ident[i])
    g[i] -= f(X, Y, w - eps * ident[i])
    g[i] /= 2 * eps

  return g


def train_w(X, Y, C=0.1):
  def f(w):
    return -log_likelihood(X, Y, w, C)

  def fprime(w):
    return -log_likelihood_grad(X, Y, w, C)

  K = X.shape[1]
  initial_guess = np.zeros(K)

  return scipy.optimize.fmin_bfgs(f, initial_guess, fprime, disp=False)

def accuracy(X, Y, w):
  print('calculating accuracy')
  n_correct = 0
  for i in range(len(X)):
    if predict(w, X[i]) == Y[i]:
      n_correct += 1
  return n_correct * 1.0 / len(X)

def fold(arr, K, i):
  N = len(arr)
  size = np.ceil(1.0 * N / K)
  arange = np.arange(N) # all indices
  heldout = np.logical_and(i * size <= arange, arange < (i+1) * size)
  rest = np.logical_not(heldout)
  h, r = arr[heldout], arr[rest]
  del heldout
  del rest
  return h,r

def kfold(arr, K):
  return [fold(arr, K, i) for i in range(K)]

def avg_accuracy(all_X, all_Y, C):
  s = 0
  K = len(all_X)
  for i in range(K):
    X_heldout, X_rest = all_X[i]
    Y_heldout, Y_rest = all_Y[i]
    w = train_w(X_rest, Y_rest, C)
    s += accuracy(X_heldout, Y_heldout, w)
  return s * 1.0 / K

def train_C(X, Y, K=10):
  all_C = np.arange(0, 1, 0.1) # the values of C to try out
  all_X = kfold(X, K)
  all_Y = kfold(Y, K)
  all_acc = np.array([avg_accuracy(all_X, all_Y, C) for C in all_C])
  return all_C[all_acc.argmax()]



def test_log_likelihood_grad(X, Y):
  n_attr = X.shape[1]
  w = np.array([1.0 / n_attr] * n_attr)

  print "with regularization"
  print log_likelihood_grad(X, Y, w)
  print grad_num(X, Y, w, log_likelihood)

  print "without regularization"
  print log_likelihood_grad(X, Y, w, C=0)
  print grad_num(X, Y, w, lambda X,Y,w: log_likelihood(X,Y,w,C=0))

def load_data(folder, _id, fields=['bytes_in_flight'],count=100,typey='tcpdump', step='train'):
  print('loading data for ' + step)
  attack_collection = None
  connection = None

  try:
    connection = pymongo.Connection('localhost', 27017)
    attack_collection = connection["dapper_modular"]['attacks']
  except Exception as e:
    print("ERROR: in ingest database connection")
    print(e)
    return False

  if attack_collection is None or connection is None:
    return 2

  data_collection = connection['dapper_modular']['attack_'+folder+"_events"]

  attack = attack_collection.find_one({"id":_id})

  data_query = dict()
  data_query['type'] = typey
  data_query['is_malicious'] = False
  attack_query = dict()
  attack_query['type'] = typey
  attack_query['is_malicious'] = True

  #make sure we have separation of data
  if 'train' in step:
    data_query["epoch"] = {"$gte":attack['start_epoch'],"$lte":attack['end_epoch']}

  attack_cursor = data_collection.find(attack_query)
  data_cursor = data_collection.find(data_query, limit=count)

  d_X_is, d_Y_is = get_components(data_cursor,fields)
  a_X_is, a_Y_is = get_components(attack_cursor,fields)
  
  d_X_is.extend(a_X_is)
  d_Y_is.extend(a_Y_is)

  X = np.vstack(tuple(d_X_is))
  Y = np.vstack(tuple(d_Y_is))
  del data_cursor
  del attack_cursor
  del d_Y_is
  del d_X_is
  return X,Y

def get_components(cursor,fields):
  X_is = []
  Y_is = []

  for e in cursor:
    cols = []
    for f in fields:
      if type(e[f]) == list:
        #take the first one
        cols.append(e[f][0])
      else:
        cols.append(e[f])
    try:
      x_i = np.array([1]+cols)
      X_is.append(x_i)
    except ValueError as e:
      print(cols)
      print(e)

    if e['is_malicious']:
      y_i = 1
    else:
      y_i = 0
    Y_is.append(y_i)
  return X_is, Y_is

def LR(args):

  if type(args) == dict:
    folder = args['folder']
    _id = args['id']
    count = args['count']
    fields = args['fields']
  else:
    folder = args.folder
    _id = args.id
    count = int(args.count)





  C = None
  X_train, Y_train = load_data(folder,_id,count=count,fields=fields)
  # Uncomment the line below to check the gradient calculations
  #test_log_likelihood_grad(X_train, Y_train); exit()
  start = time.time()

  #C = train_C(X_train, Y_train)
  #print "C was", C
  w = train_w(X_train, Y_train)

  del X_train
  del Y_train

  X_test, Y_test = load_data(folder, _id, step="test")
  acc = accuracy(X_test, Y_test, w)

  del X_test
  del Y_test

  return acc,w

def test(args):
  if type(args) == dict:
    folder = args['folder']
    _id = args['id']
    count = args['count']
    fields = args['fields']
  else:
    folder = args.folder
    _id = args.id
  print("testing Logistic Regression package")
  X, Y = load_data(folder,_id,count=count,step='test',fields=fields)
  print(X[:10])
  print(Y[:10])


if __name__=="__main__":
  parser = argparse.ArgumentParser("Logistic Regression functionality for DAPPER")
  subparsers = parser.add_subparsers()

  parser.add_argument('--folder', dest="folder")
  parser.add_argument("--id", dest="id")
  parser.set_defaults(func=LR)
  #add LR parser
  LR_parser = subparsers.add_parser("lr")
  LR_parser.add_argument('--folder', dest="folder")
  LR_parser.add_argument("--id", dest="id")
  LR_parser.add_argument('--count', dest='count')
  LR_parser.add_argument('--num_fields', dest='field_indx')
  LR_parser.set_defaults(func=LR)

  #add test parser
  #test_parser = subparsers.add_parser("test")
  #test_parser.add_argument('folder')
  #test_parser.add_argument("id")
  #test_parser.set_defaults(func=test)

  #make it happen
  args = parser.parse_args()
  args.func(args)
  #LR({"folder":"5s6","id":"2"})
