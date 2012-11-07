__author__ = 'matthew'

import argparse
import numpy as np
import scipy.optimize
import pymongo
import time

def logistic(z):
  return 1.0 / (1.0 + np.exp(-z))

def predict(w, x):
  return logistic(np.dot(w, x)) > 0.5 or -1

def log_likelihood(X, Y, w, C=0.1):
  return np.sum(np.log(logistic(Y * np.dot(X, w)))) - C/2 * np.dot(w, w)

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
  return arr[heldout], arr[rest]

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

def load_data(folder, id, typey='tcpdump', step='train'):
  attackCollection = None
  connection = None

  try:
    connection = pymongo.Connection('localhost', 27017)
    attackCollection = connection["dapper_modular"]['attacks']
  except Exception as e:
    print("ERROR: in ingest database connection")
    print(e)
    return False

  if attackCollection is None or connection is None:
    return 2

  attack = attackCollection.find_one({"id":id})

  query = dict()
  query['type'] = typey

  if 'train' in step:
    print("attack duration",attack['end_epoch']-attack['start_epoch'])
    query["epoch"] = {"$gte":attack['start_epoch'],"$lte":attack['end_epoch']}

  dataCollection = connection['dapper_modular']['attack_'+folder+"_events"]

  print(query)
  cursor = dataCollection.find(query)

  X_is = []
  Y_is = []
  for e in cursor:
    x_i = np.array([1]+[e['bytes_in_flight']])
    X_is.append(x_i)

    y_i = 1 if e['is_malicious'] else 0
    Y_is.append(y_i)


  X = np.vstack(tuple(X_is))
  Y = np.vstack(tuple(Y_is))

  return X,Y

def LR(args):
  X_train, Y_train = load_data(args.folder,args.id)

  # Uncomment the line below to check the gradient calculations
  #test_log_likelihood_grad(X_train, Y_train); exit()
  start = time.time()
  C = train_C(X_train, Y_train)
  print "C was", C
  one = time.time()
  print "train C took: ", one - start
  w = train_w(X_train, Y_train, C)
  two = time.time()
  print "w was", w
  print "train w took: ", two - one

  #X_test, Y_test = load_data(args.id,"test")
  #print "accuracy was", accuracy(X_test, Y_test, w)


def test(args):
  print("testing Logistic Regression package")
  X, Y = load_data(args.folder,args.id)
  print(X[:10])
  print(Y[:10])


if __name__=="__main__":
  parser = argparse.ArgumentParser("Logistic Regression functionality for DAPPER")
  subparsers = parser.add_subparsers()

  #add LR parser
  LR_parser = subparsers.add_parser("lr")
  LR_parser.add_argument('folder')
  LR_parser.add_argument("id")
  LR_parser.set_defaults(func=LR)

  #add test parser
  test_parser = subparsers.add_parser("test")
  test_parser.add_argument('folder')
  test_parser.add_argument("id")
  test_parser.set_defaults(func=test)

  #make it happen
  args = parser.parse_args()
  args.func(args)